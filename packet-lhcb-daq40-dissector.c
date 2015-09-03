#include "config.h"
#include "packet-lhcb-daq40-dissector.h"

#include <epan/packet.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MEP_METADATA_PORT 29899
#define MEP_DATA_PORT 1235

static int proto_mep = -1;
static int proto_meta = -1;
static int proto_data = -1;
static int proto_payload = -1;

static int hf_data_evid = -1;
static int hf_data_type = -1;
static int hf_data_size = -1;
static int hf_data_payload = -1;
//static int hf_data_payload_size = -1;

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
static gint ett_meta = -1;
static gint ett_frag = -1;
static gint ett_data = -1;
static gint ett_payload = -1;

static struct daq40_config cfg = {0};

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

static void dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *pi = NULL;
    proto_tree *mep_tree = NULL;
    proto_item *data_root = NULL;
    proto_tree *data_tree = NULL;
    proto_item *payload_root = NULL;
    proto_tree *payload_tree = NULL;

    int offset = 0;
//    int num_events = 0;
    int payload_size = 0;
    guint16 size = 0;
    guint16 headersize = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEP Data");
    debug_print("*** Dissect MEP2 data \n");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    if (tree) {
        pi = proto_tree_add_item(tree, proto_mep, tvb, 0, -1, ENC_NA);
        mep_tree = proto_item_add_subtree(pi, ett_mep);
        data_root = proto_tree_add_item(mep_tree, proto_data, tvb, 0, -1, ENC_NA);
        data_tree = proto_item_add_subtree(data_root, ett_data);

//       while (num_events >) {
            proto_tree_add_item(data_tree, hf_data_evid, tvb, offset, 8, ENC_BIG_ENDIAN);  // 64bit = 8 byte
            offset += 8;
            proto_tree_add_item(data_tree, hf_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(data_tree, hf_data_size, tvb, offset, 2, ENC_BIG_ENDIAN);
            size = tvb_get_bits16(tvb, offset*8, 16, FALSE);
            debug_print("size: %hu\n", size);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Event size: %hu", size);

            /* Payload */
            headersize =  64 + 8 + 16;
            payload_size = size - headersize;
            debug_print("payload size: %d\n", payload_size);

            payload_root = proto_tree_add_item(data_tree, proto_payload, tvb, offset, -1, ENC_NA);
            payload_tree = proto_item_add_subtree(payload_root, ett_payload);
            offset += 2;
            proto_tree_add_item(payload_tree, hf_data_payload, tvb, offset, -1, ENC_BIG_ENDIAN);
//       }
    }
}

static void dissect_meta(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *pi = NULL;
    proto_tree *mep_tree = NULL;
    proto_item *meta_root = NULL;
    proto_tree *meta_tree = NULL;
    proto_item *frag_item = NULL;
    proto_tree *frag_tree = NULL;

    int offset = 0;
    guint16 num_frags = 0;
    int data_offset = 0;
    int i, j;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEP2 metadata");
    debug_print("*** Dissect MEP metadata \n");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    if (tree) {     /* return details */
        pi = proto_tree_add_item(tree, proto_mep, tvb, 0, -1, ENC_NA);
        mep_tree = proto_item_add_subtree(pi, ett_meta);
        meta_root = proto_tree_add_item(mep_tree, proto_meta, tvb, 0, -1, ENC_NA);
        meta_tree = proto_item_add_subtree(meta_root, ett_meta);

/***  MEP header ***/
        proto_tree_add_item(meta_tree, hf_meta_seqn, tvb, offset, 4, ENC_BIG_ENDIAN);  // 32bit = 4 byte
        guint32 seqn = tvb_get_bits32(tvb, offset*8, 32, FALSE);
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
            int start_offset = offset;
            debug_print("\n*** Frag num: %d\n", i);
            uint32_t data = tvb_get_bits32(tvb, data_offset, 32, ENC_BIG_ENDIAN);
            debug_print("data: %x\n", data);
            uint32_t global_hdr = data;
            uint16_t frag_bxid = global_hdr >> 20;
            debug_print("FRG.bxid: %hu\n", frag_bxid);

            uint32_t frag_gdl = global_hdr & 0xFFFFF;
            debug_print("FRG.gdl: %u\n", frag_gdl);

            frag_item = proto_tree_add_text(meta_tree, tvb, offset, -1, "Frag #%d,FRG.bxid: %hu, FRG.gdl: %u", i, frag_bxid, frag_gdl);
            frag_tree = proto_item_add_subtree(frag_item, ett_frag);

            size_t event_bytes = GLOBAL_HEADER_BYTES + ceil(frag_gdl/8.0);
            size_t padding = event_bytes % 8 ? (8 - (event_bytes % 8)) : 0;

            proto_item *ti = proto_tree_add_bits_item(frag_tree, hf_frag_bxid_gdl, tvb, data_offset, 32, ENC_BIG_ENDIAN);
            data_offset += 32;
            for (j = 0; j < NUM_LINKS; j++) {
                debug_print("\nOPT (%d): ", j);
                debug_print("offset: %x ", offset);
                guint16 bxid = tvb_get_bits16(tvb, data_offset, BXID_SIZE, FALSE);
                proto_tree_add_bits_item(frag_tree, hf_opt_bxid, tvb, data_offset, BXID_SIZE, FALSE);
                debug_print("BXID: %x at offset %d, ", bxid, data_offset);
                data_offset += BXID_SIZE;
                proto_tree_add_bits_item(frag_tree, hf_opt_data_exists, tvb, data_offset, INFO_SIZE, FALSE);
                char dataflag = tvb_get_bits8(tvb, data_offset, INFO_SIZE);
                debug_print("Data exists: %x at offset %d, ", dataflag, data_offset);
                data_offset += INFO_SIZE;
                    gint16 datalen = tvb_get_bits16(tvb, data_offset, DATALEN_BITS_SIZE, FALSE);
                if (datalen == MAX_DATALEN) {
                    datalen = FE_NZS_BITS;
                } else {
                    datalen *= 4;
                }
                    proto_tree_add_uint_bits_format_value(frag_tree, hf_opt_datalen, tvb, data_offset, DATALEN_BITS_SIZE, 0, "%u", datalen);
                    debug_print("Datalen: %hu at offset %d, ", datalen, data_offset);
                    data_offset += DATALEN_BITS_SIZE;

                if (dataflag == 0 && datalen > 0) {
                    /* Data comes next */

                    int datalen_tmp = datalen;
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
            //offset += ceil(data_offset/8.0);
        }
    }
}

void proto_register_mep(void)
{
    /* protocol subtree array*/
    static gint *ett[] = {
        &ett_mep,
        &ett_meta,
        &ett_frag,
        &ett_data,
        &ett_payload
    };
    static const value_string data_type_names[] = {
        {0x1, "First Type"},
        {0x2, "Second Type"},
        {0, NULL},
    };

    static hf_register_info hf_meta[] = {
        { &hf_meta_seqn,
            { "MEP2: Sequence number", "mep.seq",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            "seqn", HFILL }
        },
        { &hf_meta_size,
            { "MEP2: Size", "mep.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "size", HFILL }
        },
        { &hf_meta_num_frags,
            { "MEP2: Number of fragments", "mep.fragnum",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "number of fragments", HFILL }
        },
        { &hf_meta_evid,
            { "MEP2: Event id", "mep.evid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "event id", HFILL }
        },
        { &hf_frag_bxid_gdl,
            { "MEP2 FRG: BXID, GDL", "mep.frg.bxid",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            "fragment bxid & gdl", HFILL }
        },
        { &hf_frag_gdl,
            { "MEP2 FRG: gdl", "mep.frg.gdl",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            "fragment gdl", HFILL }
        },
        { &hf_opt_bxid,
            { "MEP2 OPT: bxid", "mep.opt.bxid",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            "opt bxid", HFILL }
        },
        { &hf_opt_data_exists,
            { "MEP2 OPT: Data exists flag", "mep.opt.data_flag",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            "opt dataflag", HFILL }
        },
        { &hf_opt_datalen,
            { "MEP2 OPT: data length", "mep.opt.datalen",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            "opt datalen", HFILL }
        },
        { &hf_opt_data,
            { "MEP2 OPT: data", "mep.opt.data",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            "opt data", HFILL }
        },
    };

    static hf_register_info hf_data[] = {
        { &hf_data_evid,
            { "MEP2 data: Event ID", "mep.data.evid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "evid", HFILL }
        },
        { &hf_data_type,
            { "MEP data: Type", "mep.data.type",
            FT_UINT8, BASE_DEC,
            VALS(data_type_names), 0x0,
            "data type", HFILL }
        },
        { &hf_data_size,
            { "MEP data: Size", "mep.data.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "data size", HFILL }
        },
        { &hf_data_payload,
            { "MEP data: Payload", "mep.data.payload",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "data payload", HFILL }
        },
    };


    proto_mep = proto_register_protocol (
        "MEP2 Protocol", /* name       */
        "MEP2",      /* short name */
        "mep2"       /* abbrev     */
        );


    proto_meta = proto_register_protocol (
        "MEP2 Metadata Protocol", /* name       */
        "MEP2M",      /* short name */
        "mep2meta"       /* abbrev     */
        );


    proto_data = proto_register_protocol (
        "MEP2 Data", /* name       */
        "MEP2D",      /* short name */
        "mep2data"       /* abbrev     */
        );

    proto_payload = proto_register_protocol (
        "MEP2 Data Payload", /* name       */
        "MEP2DP",      /* short name */
        "mep2datapayload"       /* abbrev     */
        );


    debug_print("*** Registering MEP2 protocol\n");

    //proto_register_field_array(proto_mep, hf_mep, array_length(hf_mep));
    proto_register_field_array(proto_meta, hf_meta, array_length(hf_meta));
    proto_register_field_array(proto_data, hf_data, array_length(hf_data));
    proto_register_subtree_array(ett, array_length(ett));

    init_cfg();
    debug_print("*** DONE \n");
}

void proto_reg_handoff_mep(void)
{
    static dissector_handle_t meta_handle;
    static dissector_handle_t data_handle;
    debug_print("*** MEP protocol handoff\n");

    meta_handle = create_dissector_handle(dissect_meta, proto_meta);
    data_handle = create_dissector_handle(dissect_data, proto_data);
    dissector_add_uint("udp.port", MEP_METADATA_PORT, meta_handle);
    dissector_add_uint("udp.port", MEP_DATA_PORT, data_handle);
}
