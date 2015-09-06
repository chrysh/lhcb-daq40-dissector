#include "config.h"
#include "packet-lhcb-daq40-dissector.h"

#include <epan/packet.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MEP_PORT 29899

static int proto_mep = -1;

static int hf_meta_seqn = -1;
static int hf_meta_size = -1;
static int hf_meta_num_frags = -1;
static int hf_meta_evid = -1;
static int hf_frag_bxid_gdl = -1;
static int hf_frag_gdl = -1;
static int hf_opt_bxid = -1;
static int hf_opt_data_exists = -1;
static int hf_opt_datalen = -1;
static int hf_opt_data = -1;

static gint ett_mep = -1;
static gint ett_frag = -1;

static struct daq40_config cfg;

static void init_cfg(void)
{
  cfg.fe_header_msb = HEADER_MSB;
  cfg.fe_frame_bits = FRAME_BITS;
  cfg.fe_bxid_bits = BXID_SIZE;
  cfg.fe_info_bits = INFO_SIZE;
  cfg.fe_datalen_bits = DATALEN_BITS_SIZE;
  cfg.fe_channel_bits = CHANNEL_BITS;
  cfg.fe_nzs_bits = NZS_BITS;
  //cfg.fe_sync_pattern = SYNC_PATTERN;
}

static void dissect_mep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *meta_root = NULL;
    proto_tree *meta_tree = NULL;
    proto_item *frag_item = NULL;
    proto_tree *frag_tree = NULL;

    int offset = 0;
    guint16 num_frags = 0;
    int data_offset = 0;
    int i, j;

    guint32 seqn = 0;
    int start_offset = 0;
    uint32_t data = 0;
    uint32_t global_hdr = 0;
    uint16_t frag_bxid = 0;
    uint32_t frag_gdl = 0;
    size_t padding = 0;
    size_t event_bytes = 0;
    guint16 bxid = 0;
    char dataflag = 0;
    gint16 datalen = 0;
    gint16 datalen_tmp = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEP");
    debug_print("*** Dissect MEP\n");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    if (tree) {     /* return details */
        meta_root = proto_tree_add_item(tree, proto_mep, tvb, 0, -1, ENC_NA);
        meta_tree = proto_item_add_subtree(meta_root, ett_mep);

/***  MEP header ***/
        proto_tree_add_item(meta_tree, hf_meta_seqn, tvb, offset, 4, ENC_BIG_ENDIAN);  // 32bit = 4 byte
        seqn = tvb_get_bits32(tvb, offset*8, 32, FALSE);
        debug_print("*** Seqn: %d\n", seqn);
        offset += 4;
        proto_tree_add_item(meta_tree, hf_meta_size, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(meta_tree, hf_meta_num_frags, tvb, offset, 2, ENC_BIG_ENDIAN);
        num_frags = tvb_get_bits16(tvb, offset*8, 16, FALSE);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Num. frags: %hu", num_frags);
        offset += 2;
        proto_tree_add_item(meta_tree, hf_meta_evid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

/***    MEP MSB prot ***/
        for (i = 0; i < num_frags; i++) {

            data_offset = offset*8;
            start_offset = offset;
            debug_print("\n*** Frag num: %d\n", i);
            data = tvb_get_bits32(tvb, data_offset, 32, ENC_BIG_ENDIAN);
            debug_print("data: %x\n", data);
            global_hdr = data;
            frag_bxid = global_hdr >> 20;
            debug_print("FRG.bxid: %hu\n", frag_bxid);

            frag_gdl = global_hdr & 0xFFFFF;
            debug_print("FRG.gdl: %u\n", frag_gdl);

            frag_item = proto_tree_add_text(meta_tree, tvb, offset, -1, "Frag #%d,FRG.bxid: %hu, FRG.gdl: %u", i, frag_bxid, frag_gdl);
            frag_tree = proto_item_add_subtree(frag_item, ett_frag);

            event_bytes = GLOBAL_HEADER_BYTES + ceil(frag_gdl/8.0);
            padding = event_bytes % 8 ? (8 - (event_bytes % 8)) : 0;

            proto_tree_add_bits_item(frag_tree, hf_frag_bxid_gdl, tvb, data_offset, 32, ENC_BIG_ENDIAN);
            data_offset += 32;
            for (j = 0; j < NUM_LINKS; j++) {
                debug_print("\nOPT (%d): ", j);
                debug_print("offset: %x ", offset);
                bxid = tvb_get_bits16(tvb, data_offset, cfg.fe_bxid_bits, FALSE);
                proto_tree_add_bits_item(frag_tree, hf_opt_bxid, tvb, data_offset, cfg.fe_bxid_bits, FALSE);
                debug_print("BXID: %x at offset %d, ", bxid, data_offset);
                data_offset += cfg.fe_bxid_bits;
                proto_tree_add_bits_item(frag_tree, hf_opt_data_exists, tvb, data_offset, cfg.fe_info_bits, FALSE);
                dataflag = tvb_get_bits8(tvb, data_offset, cfg.fe_info_bits);
                debug_print("Data exists: %x at offset %d, ", dataflag, data_offset);
                data_offset += cfg.fe_info_bits;
                datalen = tvb_get_bits16(tvb, data_offset, cfg.fe_datalen_bits, FALSE);
                if (datalen == MAX_DATALEN) {
                    datalen = FE_NZS_BITS;
                } else {
                    datalen *=cfg.fe_channel_bits;
                }
                    proto_tree_add_uint_bits_format_value(frag_tree, hf_opt_datalen, tvb, data_offset, cfg.fe_datalen_bits, 0, "%u", datalen);
                    debug_print("Datalen: %hu at offset %d, ", datalen, data_offset);
                    data_offset += cfg.fe_datalen_bits;

                if (dataflag == 0 && datalen > 0) {
                    /* Data comes next */

                    datalen_tmp = datalen;
                    if (datalen > 64) {
                        datalen_tmp = 64;
                    }
                    proto_tree_add_bits_item(frag_tree, hf_opt_data, tvb, data_offset, datalen_tmp, ENC_NA);
                    debug_print("Data: %x at offset %d, ", data, data_offset);
                    data_offset += datalen;
                    col_clear(pinfo->cinfo,COL_INFO);
                }
            }
            debug_print("Advancing by %d bytes\n", event_bytes + padding);
            offset = start_offset + event_bytes + padding;
        }
    }
}

void proto_register_mep(void)
{
    /* protocol subtree array*/
    static gint *ett[] = {
        &ett_mep,
        &ett_frag,
    };

    static hf_register_info hf_mep[] = {
        { &hf_meta_seqn,
            { "MEP: Sequence number", "mep.seq",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            "seqn", HFILL }
        },
        { &hf_meta_size,
            { "MEP: Size", "mep.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "size", HFILL }
        },
        { &hf_meta_num_frags,
            { "MEP: Number of fragments", "mep.fragnum",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "number of fragments", HFILL }
        },
        { &hf_meta_evid,
            { "MEP: Event id", "mep.evid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "event id", HFILL }
        },
        { &hf_frag_bxid_gdl,
            { "MEP FRG: BXID, GDL", "mep.frg.bxid",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            "fragment bxid & gdl", HFILL }
        },
        { &hf_frag_gdl,
            { "MEP FRG: gdl", "mep.frg.gdl",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            "fragment gdl", HFILL }
        },
        { &hf_opt_bxid,
            { "MEP OPT: bxid", "mep.opt.bxid",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            "opt bxid", HFILL }
        },
        { &hf_opt_data_exists,
            { "MEP OPT: Data exists flag", "mep.opt.data_flag",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            "opt dataflag", HFILL }
        },
        { &hf_opt_datalen,
            { "MEP OPT: data length", "mep.opt.datalen",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            "opt datalen", HFILL }
        },
        { &hf_opt_data,
            { "MEP OPT: data", "mep.opt.data",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            "opt data", HFILL }
        },
    };

    proto_mep = proto_register_protocol (
        "MEP Protocol", /* name       */
        "MEP",      /* short name */
        "mep"       /* abbrev     */
        );

    debug_print("*** Registering MEP protocol\n");

    proto_register_field_array(proto_mep, hf_mep, array_length(hf_mep));
    proto_register_subtree_array(ett, array_length(ett));

    init_cfg();
    debug_print("*** DONE \n");
}

void proto_reg_handoff_mep(void)
{
    static dissector_handle_t mep_handle;
    debug_print("*** MEP protocol handoff\n");

    mep_handle = create_dissector_handle(dissect_mep, proto_mep);
    dissector_add_uint("udp.port", MEP_PORT, mep_handle);
}
