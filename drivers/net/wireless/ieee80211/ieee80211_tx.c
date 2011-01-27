/******************************************************************************
  
  Copyright(c) 2003 - 2004 Intel Corporation. All rights reserved.
  
  This program is free software; you can redistribute it and/or modify it 
  under the terms of version 2 of the GNU General Public License as 
  published by the Free Software Foundation.
  
  This program is distributed in the hope that it will be useful, but WITHOUT 
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
  more details.
  
  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 59 
  Temple Place - Suite 330, Boston, MA  02111-1307, USA.
  
  The full GNU General Public License is included in this distribution in the
  file called LICENSE.
  
  Contact Information:
  James P. Ketrenos <ipw2100-admin@linux.intel.com>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

******************************************************************************/
#include <linux/compiler.h>
#include <linux/config.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/in6.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/wireless.h>
#include <linux/etherdevice.h>
#include <asm/uaccess.h>

#include "ieee80211.h"


/*


802.11 Data Frame 

      ,-------------------------------------------------------------------.
Bytes |  2   |  2   |    6    |    6    |    6    |  2   | 0..2312 |   4  |
      |------|------|---------|---------|---------|------|---------|------|
Desc. | ctrl | dura |  DA/RA  |   TA    |    SA   | Sequ |  Frame  |  fcs |
      |      | tion | (BSSID) |         |         | ence |  data   |      |
      `--------------------------------------------------|         |------'
Total: 28 non-data bytes                                 `----.----'  
                                                              |
       .- 'Frame data' expands to <---------------------------'
       |
       V
      ,---------------------------------------------------.
Bytes |  1   |  1   |    1    |    3     |  2   |  0-2304 |
      |------|------|---------|----------|------|---------|
Desc. | SNAP | SNAP | Control |Eth Tunnel| Type | IP      |
      | DSAP | SSAP |         |          |      | Packet  |
      | 0xAA | 0xAA |0x03 (UI)|0x00-00-F8|      |         |
      `-----------------------------------------|         |
Total: 8 non-data bytes                         `----.----'
                                                     |
       .- 'IP Packet' expands, if WEP enabled, to <--'
       |
       V
      ,-----------------------.
Bytes |  4  |   0-2296  |  4  |
      |-----|-----------|-----|
Desc. | IV  | Encrypted | ICV |
      |     | IP Packet |     |
      `-----------------------'
Total: 8 non-data bytes


802.3 Ethernet Data Frame 

      ,-----------------------------------------.
Bytes |   6   |   6   |  2   |  Variable |   4  |
      |-------|-------|------|-----------|------|
Desc. | Dest. | Source| Type | IP Packet |  fcs |
      |  MAC  |  MAC  |      |           |      |
      `-----------------------------------------'
Total: 18 non-data bytes

In the event that fragmentation is required, the incoming payload is split into
N parts of size ieee->fts.  The first fragment contains the SNAP header and the
remaining packets are just data.

If encryption is enabled, each fragment payload size is reduced by enough space
to add the prefix and postfix (IV and ICV totalling 8 bytes in the case of WEP)
So if you have 1500 bytes of payload with ieee->fts set to 500 without 
encryption it will take 3 frames.  With WEP it will take 4 frames as the 
payload of each frame is reduced to 492 bytes.

* SKB visualization
* 
*  ,- skb->data 
* |
* |    ETHERNET HEADER        ,-<-- PAYLOAD
* |                           |     14 bytes from skb->data 
* |  2 bytes for Type --> ,T. |     (sizeof ethhdr)
* |                       | | |    
* |,-Dest.--. ,--Src.---. | | |     
* |  6 bytes| | 6 bytes | | | |
* v         | |         | | | |
* 0         | v       1 | v | v           2       
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
*     ^     | ^         | ^ | 
*     |     | |         | | |  
*     |     | |         | `T' <---- 2 bytes for Type
*     |     | |         |
*     |     | '---SNAP--' <-------- 6 bytes for SNAP
*     |     |  
*     `-IV--' <-------------------- 4 bytes for IV (WEP)
*
*      SNAP HEADER
*
*/

static u8 P802_1H_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0xf8 };
static u8 RFC1042_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0x00 };

static inline int ieee80211_put_snap(u8 *data, u16 h_proto)
{
	struct ieee80211_snap_hdr *snap;
	u8 *oui;

	snap = (struct ieee80211_snap_hdr *)data;
	snap->dsap = 0xaa;
	snap->ssap = 0xaa;
	snap->ctrl = 0x03;

	if (h_proto == 0x8137 || h_proto == 0x80f3)
		oui = P802_1H_OUI;
	else
		oui = RFC1042_OUI;
	snap->oui[0] = oui[0];
	snap->oui[1] = oui[1];
	snap->oui[2] = oui[2];

	*(u16 *)(data + SNAP_SIZE) = htons(h_proto);

	return SNAP_SIZE + sizeof(u16);
}

#ifdef CONFIG_IEEE80211_CRYPT
static inline int ieee80211_encrypt_fragment(
	struct ieee80211_device *ieee, 
	struct sk_buff *frag,
	int hdr_len)
{
	struct ieee80211_crypt_data* crypt = ieee->crypt[ieee->tx_keyidx];
	int res;
#ifdef CONFIG_IEEE80211_WPA
	struct ieee80211_hdr *header;
	
	if (ieee->tkip_countermeasures &&
	    crypt && crypt->ops && strcmp(crypt->ops->name, "TKIP") == 0) {
		header = (struct ieee80211_hdr *) frag->data;
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: TKIP countermeasures: dropped "
			       "TX packet to " MAC_FMT "\n",
			       ieee->dev->name, MAC_ARG(header->addr1));
		}
		return -1;
	}
#endif
	/* To encrypt, frame format is:
	 * IV (4 bytes), clear payload (including SNAP), ICV (4 bytes) */

	// PR: FIXME: Copied from hostap. Check fragmentation/MSDU/MPDU encryption.
	/* Host-based IEEE 802.11 fragmentation for TX is not yet supported, so
	 * call both MSDU and MPDU encryption functions from here. */
	atomic_inc(&crypt->refcnt);
	res = 0;
	if (crypt->ops->encrypt_msdu)
		res = crypt->ops->encrypt_msdu(frag, hdr_len, crypt->priv);
	if (res == 0 && crypt->ops->encrypt_mpdu)
		res = crypt->ops->encrypt_mpdu(frag, hdr_len, crypt->priv);
	
	atomic_dec(&crypt->refcnt);
	if (res < 0) {
		printk(KERN_INFO "%s: Encryption failed: len=%d.\n",
		       ieee->dev->name, frag->len);
		ieee->ieee_stats.tx_discards++;
		return -1;
	}

	return 0;
}
#endif


void ieee80211_txb_free(struct ieee80211_txb *txb) {
	int i;
	if (unlikely(!txb))
		return;
	for (i = 0; i < txb->nr_frags; i++) 
		if (txb->fragments[i])
			dev_kfree_skb_any(txb->fragments[i]);
	kfree(txb);
}

struct ieee80211_txb *ieee80211_alloc_txb(int nr_frags, int txb_size,
					  int gfp_mask) {
	struct ieee80211_txb *txb;
	int i;
	txb = kmalloc(
		sizeof(struct ieee80211_txb) + (sizeof(u8*) * nr_frags), 
		gfp_mask);
	if (!txb)
		return NULL;

	memset(txb, sizeof(struct ieee80211_txb), 0);
	txb->nr_frags = nr_frags;
	txb->frag_size = txb_size;

	for (i = 0; i < nr_frags; i++) {
		txb->fragments[i] = dev_alloc_skb(txb_size);
		if (unlikely(!txb->fragments[i])) {
			i--;
			break;
		}
	}
	if (unlikely(i != nr_frags)) {
		while (i >= 0)
			dev_kfree_skb_any(txb->fragments[i--]);
		kfree(txb);
		return NULL;
	}
	return txb;
}

/* SKBs are added to the ieee->tx_queue. */
struct ieee80211_txb *ieee80211_skb_to_txb(struct ieee80211_device *ieee, 
					   struct sk_buff *skb)
{
	struct ieee80211_txb *txb;
	int i, bytes_per_frag, nr_frags, bytes_last_frag, frag_size;
	unsigned long flags;
	struct net_device_stats *stats = &ieee->stats;
	int ether_type, encrypt;
	int bytes, fc, hdr_len;
	struct sk_buff *skb_frag;
	struct ieee80211_hdr header;
	u8 dest[ETH_ALEN], src[ETH_ALEN];

#ifdef CONFIG_IEEE80211_CRYPT
	struct ieee80211_crypt_data* crypt;
#endif

	spin_lock_irqsave(&ieee->lock, flags);

	if (unlikely(skb->len < SNAP_SIZE + sizeof(u16))) {
		printk(KERN_WARNING "%s: skb too small (%d).\n",
		       ieee->dev->name, skb->len);
		goto failed;
	}

	ether_type = ntohs(((struct ethhdr *)skb->data)->h_proto);

#ifndef CONFIG_IEEE80211_CRYPT
	encrypt = 0;
#else   /* CONFIG_IEEE80211_CRYPT */
	crypt = ieee->crypt[ieee->tx_keyidx];

#ifndef CONFIG_IEEE80211_WPA
	encrypt = (ether_type != ETH_P_PAE) && 
		ieee->host_encrypt && crypt && crypt->ops;
	
#else /* CONFIG_IEEE80211_WPA */
	encrypt = !(ether_type == ETH_P_PAE && ieee->ieee_802_1x) && 
		ieee->host_encrypt && crypt && crypt->ops;

	if (!encrypt && ieee->ieee_802_1x &&
	    ieee->drop_unencrypted && ether_type != ETH_P_PAE){
		stats->tx_dropped++;
		/* FIXME: Allocate an empty txb and return it; this 
		 * isn't the best code path since an alloc/free is
		 * required for no real reason except to return a
		 * special case success code... */
		txb = ieee80211_alloc_txb(0, ieee->fts, GFP_ATOMIC);
		if (unlikely(!txb)) {
			printk(KERN_WARNING 
			       "%s: Could not allocate TXB\n",
			       ieee->dev->name);
			goto failed;
		}

		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: dropped unencrypted TX data "
			       "frame (drop_unencrypted=1)\n",
			       ieee->dev->name);
		}

		goto success;
	}

#endif /* CONFIG_IEEE80211_WPA */
	if (crypt && !encrypt && ether_type == ETH_P_PAE) 
		IEEE80211_DEBUG_EAP("TX: IEEE 802.11 - sending EAPOL frame\n");
#endif  /* CONFIG_IEEE80211_CRYPT */

	if (encrypt) {
		/* Save source and destination addresses */
		memcpy(&dest, skb->data, ETH_ALEN);
		memcpy(&src, skb->data+ETH_ALEN, ETH_ALEN);
	}

	/* Advance the SKB to the start of the payload */
	skb_pull(skb, sizeof(struct ethhdr));

	/* Determine total amount of storage required for TXB packets */
	bytes = skb->len + SNAP_SIZE + sizeof(u16);

	if (!ieee->tx_payload_only) {
		if (encrypt) 
			fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA |
				IEEE80211_FCTL_WEP;
		else
			fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA;
		
		if (ieee->iw_mode == IW_MODE_INFRA) {
			fc |= IEEE80211_FCTL_TODS;
			hdr_len = 24;
			/* To DS: Addr1 = BSSID, Addr2 = SA, 
			   Addr3 = DA */
			memcpy(&header.addr1, ieee->bssid, ETH_ALEN);
			memcpy(&header.addr2, &src, ETH_ALEN);
			memcpy(&header.addr3, &dest, ETH_ALEN);
		} else if (ieee->iw_mode == IW_MODE_ADHOC) {
			/* not From/To DS: Addr1 = DA, Addr2 = SA, 
			   Addr3 = BSSID */
			memcpy(&header.addr1, dest, ETH_ALEN);
			memcpy(&header.addr2, src, ETH_ALEN);
			memcpy(&header.addr3, ieee->bssid, ETH_ALEN);
		} 		
		header.frame_ctl = cpu_to_le16(fc);
		hdr_len = IEEE80211_3ADDR_SIZE;
	} else 
		hdr_len = 0;
	
	/* Determine amount of payload per fragment.  Regardless of if
	 * this stack is providing the full 802.11 header, one will 
	 * eventually be affixed to this fragment -- so we must account for
	 * it when determining the amount of payload space. */
	if (is_multicast_ether_addr(dest) ||
	    is_broadcast_ether_addr(dest))
		frag_size = MAX_FRAG_THRESHOLD - IEEE80211_3ADDR_SIZE;
	else
		frag_size = ieee->fts - IEEE80211_3ADDR_SIZE;

	bytes_per_frag = frag_size;

#ifdef CONFIG_IEEE80211_CRYPT
	/* Each fragment may need to have room for encryptiong pre/postfix */
	if (encrypt) 
		bytes_per_frag -= crypt->ops->extra_prefix_len +
			crypt->ops->extra_postfix_len;
#endif

	/* Number of fragments is the total bytes_per_frag / 
	 * payload_per_fragment */
	nr_frags = bytes / bytes_per_frag;
	bytes_last_frag = bytes % bytes_per_frag;
	if (bytes_last_frag)
		nr_frags++;
	else 
		bytes_last_frag = bytes_per_frag;

	/* When we allocate the TXB we allocate enough space for the reserve
	 * and full fragment bytes (bytes_per_frag doesn't include prefix and 
	 * postfix) */
	txb = ieee80211_alloc_txb(nr_frags, frag_size, GFP_ATOMIC);
	if (unlikely(!txb)) {
		printk(KERN_WARNING "%s: Could not allocate TXB\n",
		       ieee->dev->name);
		goto failed;
	}
	txb->encrypted = encrypt;
	txb->payload_size = bytes;

	for (i = 0; i < nr_frags; i++) {
		skb_frag = txb->fragments[i];

#ifdef CONFIG_IEEE80211_CRYPT
		if (encrypt) 
			skb_reserve(skb_frag, crypt->ops->extra_prefix_len);
#endif

		if (hdr_len)
 			memcpy(skb_put(skb_frag, hdr_len), &header, hdr_len);
		
		bytes = (i == nr_frags - 1) ? bytes_last_frag : bytes_per_frag;

		/* Put a SNAP header on the first fragment */
		if (i == 0) {
			ieee80211_put_snap(
				skb_put(skb_frag, SNAP_SIZE + sizeof(u16)), 
				ether_type);
			bytes -= SNAP_SIZE + sizeof(u16);
		}

		memcpy(skb_put(skb_frag, bytes), skb->data, bytes);

		/* Advance the SKB... */
		skb_pull(skb, bytes);

#ifdef CONFIG_IEEE80211_CRYPT
		/* Encryption routine will move the header forward in order
		 * to insert the IV between the header and the payload */
		if (encrypt) {
			ieee80211_encrypt_fragment(ieee, skb_frag, hdr_len);
			skb_pull(skb_frag, hdr_len);
		}
#endif
	}

	stats->tx_packets++;
	stats->tx_bytes += txb->payload_size;

#ifdef CONFIG_IEEE80211_WPA
 success:
#endif
	/* We are now done with the SKB provided to us */
	dev_kfree_skb_any(skb);
	
	spin_unlock_irqrestore(&ieee->lock, flags);

	return txb;

 failed:
	stats->tx_errors++;

	return NULL;

}

EXPORT_SYMBOL(ieee80211_skb_to_txb);
EXPORT_SYMBOL(ieee80211_txb_free);
