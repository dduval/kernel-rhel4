/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _E1000_API_H_
#define _E1000_API_H_

#include "e1000_hw.h"

s32  e1000_setup_init_funcs(struct e1000_hw *hw, bool init_device);
void e1000_remove_device(struct e1000_hw *hw);
s32  e1000_get_bus_info(struct e1000_hw *hw);
void e1000_clear_vfta(struct e1000_hw *hw);
void e1000_write_vfta(struct e1000_hw *hw, u32 offset, u32 value);
s32  e1000_force_mac_fc(struct e1000_hw *hw);
s32  e1000_check_for_link(struct e1000_hw *hw);
s32  e1000_reset_hw(struct e1000_hw *hw);
s32  e1000_init_hw(struct e1000_hw *hw);
s32  e1000_setup_link(struct e1000_hw *hw);
s32  e1000_get_speed_and_duplex(struct e1000_hw *hw, u16 *speed,
                                u16 *duplex);
s32  e1000_disable_pcie_master(struct e1000_hw *hw);
void e1000_config_collision_dist(struct e1000_hw *hw);
void e1000_rar_set(struct e1000_hw *hw, u8 *addr, u32 index);
void e1000_mta_set(struct e1000_hw *hw, u32 hash_value);
u32  e1000_hash_mc_addr(struct e1000_hw *hw, u8 *mc_addr);
void e1000_mc_addr_list_update(struct e1000_hw *hw,
                               u8 *mc_addr_list, u32 mc_addr_count,
                               u32 rar_used_count, u32 rar_count);
s32  e1000_cleanup_led(struct e1000_hw *hw);
s32  e1000_check_reset_block(struct e1000_hw *hw);
s32  e1000_blink_led(struct e1000_hw *hw);
s32  e1000_led_on(struct e1000_hw *hw);
s32  e1000_led_off(struct e1000_hw *hw);
void e1000_reset_adaptive(struct e1000_hw *hw);
void e1000_update_adaptive(struct e1000_hw *hw);
s32  e1000_get_cable_length(struct e1000_hw *hw);
s32  e1000_validate_mdi_setting(struct e1000_hw *hw);
s32  e1000_read_phy_reg(struct e1000_hw *hw, u32 offset, u16 *data);
s32  e1000_write_phy_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32  e1000_write_8bit_ctrl_reg(struct e1000_hw *hw, u32 reg,
                               u32 offset, u8 data);
s32  e1000_get_phy_info(struct e1000_hw *hw);
s32  e1000_phy_hw_reset(struct e1000_hw *hw);
s32  e1000_phy_commit(struct e1000_hw *hw);
s32  e1000_read_mac_addr(struct e1000_hw *hw);
s32  e1000_update_nvm_checksum(struct e1000_hw *hw);
s32  e1000_validate_nvm_checksum(struct e1000_hw *hw);
s32  e1000_read_nvm(struct e1000_hw *hw, u16 offset, u16 words, u16 *data);
s32  e1000_write_nvm(struct e1000_hw *hw, u16 offset, u16 words,
                     u16 *data);
s32  e1000_wait_autoneg(struct e1000_hw *hw);
s32  e1000_set_d3_lplu_state(struct e1000_hw *hw, bool active);
s32  e1000_set_d0_lplu_state(struct e1000_hw *hw, bool active);
bool e1000_enable_mng_pass_thru(struct e1000_hw *hw);


/* TBI_ACCEPT macro definition:
 *
 * This macro requires:
 *      adapter = a pointer to struct e1000_hw
 *      status = the 8 bit status field of the RX descriptor with EOP set
 *      error = the 8 bit error field of the RX descriptor with EOP set
 *      length = the sum of all the length fields of the RX descriptors that
 *               make up the current frame
 *      last_byte = the last byte of the frame DMAed by the hardware
 *      max_frame_length = the maximum frame length we want to accept.
 *      min_frame_length = the minimum frame length we want to accept.
 *
 * This macro is a conditional that should be used in the interrupt
 * handler's Rx processing routine when RxErrors have been detected.
 *
 * Typical use:
 *  ...
 *  if (TBI_ACCEPT) {
 *      accept_frame = 1;
 *      e1000_tbi_adjust_stats(adapter, MacAddress);
 *      frame_length--;
 *  } else {
 *      accept_frame = 0;
 *  }
 *  ...
 */

/* The carrier extension symbol, as received by the NIC. */
#define CARRIER_EXTENSION   0x0F

#define TBI_ACCEPT(a, status, errors, length, last_byte) \
    (e1000_tbi_sbp_enabled_82543(a) && \
     (((errors) & E1000_RXD_ERR_FRAME_ERR_MASK) == E1000_RXD_ERR_CE) && \
     ((last_byte) == CARRIER_EXTENSION) && \
     (((status) & E1000_RXD_STAT_VP) ? \
          (((length) > ((a)->mac.min_frame_size - VLAN_TAG_SIZE)) && \
           ((length) <= ((a)->mac.max_frame_size + 1))) : \
          (((length) > (a)->mac.min_frame_size) && \
           ((length) <= ((a)->mac.max_frame_size + VLAN_TAG_SIZE + 1)))))

#endif