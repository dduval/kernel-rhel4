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

/* ethtool register test data */
struct igb_reg_test {
	u16 reg;
	u8  array_len;
	u8  test_type;
	u32 mask;
	u32 write;
};

/* In the hardware, registers are laid out either singly, in arrays
 * spaced 0x100 bytes apart, or in contiguous tables.  We assume
 * most tests take place on arrays or single registers (handled
 * as a single-element array) and special-case the tables.
 * Table tests are always pattern tests.
 *
 * We also make provision for some required setup steps by specifying
 * registers to be written without any read-back testing.
 */

#define PATTERN_TEST	1
#define SET_READ_TEST	2
#define WRITE_NO_TEST	3
#define TABLE32_TEST	4
#define TABLE64_TEST_LO	5
#define TABLE64_TEST_HI	6

/* default register test */
static struct igb_reg_test reg_test_82575[] = {
	{ E1000_FCAL,	1, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ E1000_FCAH,	1, PATTERN_TEST, 0x0000FFFF, 0xFFFFFFFF },
	{ E1000_FCT,	1, PATTERN_TEST, 0x0000FFFF, 0xFFFFFFFF },
	{ E1000_VET,	1, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ E1000_RDBAL,	4, PATTERN_TEST, 0xFFFFFF80, 0xFFFFFFFF },
	{ E1000_RDBAH,	4, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ E1000_RDLEN,	4, PATTERN_TEST, 0x000FFF80, 0x000FFFFF },
	/* Enable all four RX queues before testing. */
	{ E1000_RXDCTL,	4, WRITE_NO_TEST, 0, E1000_RXDCTL_QUEUE_ENABLE },
	/* RDH is read-only for 82575, only test RDT. */
	{ E1000_RDT0,	4, PATTERN_TEST, 0x0000FFFF, 0x0000FFFF },
	{ E1000_RXDCTL,	4, WRITE_NO_TEST, 0, 0 },
	{ E1000_FCRTH,	1, PATTERN_TEST, 0x0000FFF0, 0x0000FFF0 },
	{ E1000_FCTTV,	1, PATTERN_TEST, 0x0000FFFF, 0x0000FFFF },
	{ E1000_TIPG,	1, PATTERN_TEST, 0x3FFFFFFF, 0x3FFFFFFF },
	{ E1000_TDBAL,	4, PATTERN_TEST, 0xFFFFFF80, 0xFFFFFFFF },
	{ E1000_TDBAH,	4, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ E1000_TDLEN,	4, PATTERN_TEST, 0x000FFF80, 0x000FFFFF },
	{ E1000_RCTL,	1, SET_READ_TEST, 0xFFFFFFFF, 0x00000000 },
	{ E1000_RCTL,	1, SET_READ_TEST, 0x04CFB3FE, 0x003FFFFB },
	{ E1000_RCTL,	1, SET_READ_TEST, 0x04CFB3FE, 0xFFFFFFFF },
	{ E1000_TCTL,	1, SET_READ_TEST, 0xFFFFFFFF, 0x00000000 },
	{ E1000_TXCW,	1, PATTERN_TEST, 0xC000FFFF, 0x0000FFFF },
	{ E1000_RA,	16, TABLE64_TEST_LO,
						0xFFFFFFFF, 0xFFFFFFFF },
	{ E1000_RA,	16, TABLE64_TEST_HI,
						0x800FFFFF, 0xFFFFFFFF },
	{ E1000_MTA,	128, TABLE32_TEST,
						0xFFFFFFFF, 0xFFFFFFFF },
	{ 0, 0, 0, 0 }
};