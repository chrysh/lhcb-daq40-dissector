/* packet-lhcb-daq40-dissector.h
 * By Christina Quast <chrysh.ng+github@gmail.com>
 * Copyright 1998 Christina Quast
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdbool.h>

#define GLOBAL_HEADER_BYTES 4
#define NUM_LINKS   3

#define DEBUG   0
#define debug_print(fmt, ...) \
            do { if(DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

// FIXME: The size should be read from a config file
/*  Sizes defined in bits    */
#define AMC40_LAPP_DP_FF_MSB_WIDE_BX12_MENTOR

/* FV */
#ifdef AMC40_LAPP_DP_FF_MSB_WIDE_BX12_MENTOR
#define BXID_SIZE           12
#define INFO_SIZE           1
#define DATALEN_BITS_SIZE   7
#define FV
#elif defined AMC40_LAPP_DP_FV_MSB_GBT_BX12_MENTOR
#define BXID_SIZE           12
#define INFO_SIZE           4
#define DATALEN_BITS_SIZE   7
#define FV
#elif defined AMC40_LAPP_DP_FV_MSB_WIDE_BX8_MENTOR
#define BXID_SIZE           8
#define INFO_SIZE           1
#define DATALEN_BITS_SIZE   7
#define FV
#elif defined AMC40_LAPP_DP_FV_MSB_GBT_BX8_MENTOR
#define BXID_SIZE           8
#define INFO_SIZE           1
#define DATALEN_BITS_SIZE   7
#define FV

/* FF */
#elif defined AMC40_LAPP_DP_FF_MSB_WIDE_BX12_MENTOR
#define BXID_SIZE           12
#define INFO_SIZE           4
#define DATALEN_BITS_SIZE   0
#define FF
#elif defined AMC40_LAPP_DP_FF_MSB_WIDE_BX8_MENTOR
#define BXID_SIZE           8
#define INFO_SIZE           8
#define DATALEN_BITS_SIZE   0
#define FF
#elif defined AMC40_LAPP_DP_FF_MSB_GBT_BX12_MENTOR
#define BXID_SIZE           12
#define INFO_SIZE           4
#define DATALEN_BITS_SIZE   0
#define FF
#elif defined AMC40_LAPP_DP_FF_MSB_GBT_BX8_MENTOR
#define BXID_SIZE           8
#define INFO_SIZE           8
#define DATALEN_BITS_SIZE   0
#define FF
#endif

#ifdef FV
#define CHANNEL_BITS 4
#else
#define CHANNEL_BITS 8
#endif

/* FIXME: calculate it once? */
#define MAX_DATALEN     127     // 0b1111111
#define FE_NZS_BITS     200

/* Default config vals */
#define HEADER_MSB  true
#define FRAME_BITS  80
#define NZS_BITS    64


struct daq40_config {
  bool fe_header_msb;
  int fe_frame_bits;
  int fe_bxid_bits;
  int fe_info_bits;
  int fe_datalen_bits;
  bool fe_datalen_always;
  int fe_channel_bits;
  int fe_nzs_bits;
  bool fe_is_upstream;
  int fe_format;

  int dp_bxid_bits;
};
