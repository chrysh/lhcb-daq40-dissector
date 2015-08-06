#include "config.h"
#include <epan/packet.h>
#include <stdio.h>
#define MEP_METADATA_PORT 1234
#define MEP_DATA_PORT 1235

static int proto_mep = -1;
static int proto_meta = -1;
static int proto_data = -1;
static int proto_payload = -1;

static int hf_meta_IDO = -1;
static int hf_meta_baseaddr = -1;
static int hf_meta_num_events = -1;
static int hf_meta_evid_size = -1;
static int hf_data_evid = -1;
static int hf_data_type = -1;
static int hf_data_size = -1;
static int hf_data_payload = -1;
//static int hf_data_payload_size = -1;

static gint ett_mep = -1;
static gint ett_meta = -1;
static gint ett_data = -1;
static gint ett_payload = -1;

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
    printf("*** Dissect MEP2 data \n");
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
            printf("blubb\n");
            offset += 1;
            proto_tree_add_item(data_tree, hf_data_size, tvb, offset, 2, ENC_BIG_ENDIAN);
            size = tvb_get_bits16(tvb, offset*8, 16, FALSE);
            printf("size: %hu\n", size);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Event size: %hu", size);

            /* Payload */
            headersize =  64 + 8 + 16;
            payload_size = size - headersize;
            printf("payload size: %d\n", payload_size);

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
    int offset = 0;
    int num_events = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEP2 metadata");
    printf("*** Dissect MEP metadata \n");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    if (tree) {     /* return details */
        pi = proto_tree_add_item(tree, proto_mep, tvb, 0, -1, ENC_NA);
        mep_tree = proto_item_add_subtree(pi, ett_meta);
        meta_root = proto_tree_add_item(mep_tree, proto_meta, tvb, 0, -1, ENC_NA);
        meta_tree = proto_item_add_subtree(meta_root, ett_meta);

        proto_tree_add_item(meta_tree, hf_meta_IDO, tvb, offset, 8, ENC_BIG_ENDIAN);  // 64bit = 8 byte
        offset += 8;
        proto_tree_add_item(meta_tree, hf_meta_baseaddr, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(meta_tree, hf_meta_num_events, tvb, offset, 1, ENC_BIG_ENDIAN);
        num_events = tvb_get_bits8(tvb, offset, 8);
        printf("Number of events: %d\n", num_events);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Num. events: %d", num_events);
        /* FIXME: should we construct an event ID to event size mapping here? */
        offset += 1;
        while (num_events > 0) {
            proto_tree_add_item(meta_tree, hf_meta_evid_size, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            num_events--;
        }
    }
}

void proto_register_mep(void)
{
    /* protocol subtree array*/
    static gint *ett[] = {
        &ett_mep,
        &ett_meta,
        &ett_data,
        &ett_payload
    };
    static const value_string data_type_names[] = {
        {0x1, "Type 1"},
        {0x2, "Type 2"},
        {0, NULL},
    };

    static hf_register_info hf_meta[] = {
        { &hf_meta_IDO,
            { "MEP2 meta: Base id", "mep.meta.id0",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "id0", HFILL }
        },
        { &hf_meta_baseaddr,
            { "MEP2 meta: Base address", "mep.meta.baseaddr",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            "base address", HFILL }
        },
        { &hf_meta_num_events,
            { "MEP2 meta: Number of events", "mep.meta.numev",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            "number of events", HFILL }
        },
// FIXME: how to implement a variable number of fields?
        { &hf_meta_evid_size,
            { "MEP2 meta: Event ID0 size", "mep.meta.evid0size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "event size", HFILL }
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


    printf("*** Registering MEP2 protocol\n");

    //proto_register_field_array(proto_mep, hf_mep, array_length(hf_mep));
    proto_register_field_array(proto_meta, hf_meta, array_length(hf_meta));
    proto_register_field_array(proto_data, hf_data, array_length(hf_data));
    proto_register_subtree_array(ett, array_length(ett));
    printf("*** DONE \n");
}

void proto_reg_handoff_mep(void)
{
    static dissector_handle_t meta_handle;
    static dissector_handle_t data_handle;
    printf("*** MEP protocol handoff\n");

    meta_handle = create_dissector_handle(dissect_meta, proto_meta);
    data_handle = create_dissector_handle(dissect_data, proto_data);
    dissector_add_uint("udp.port", MEP_METADATA_PORT, meta_handle);
    dissector_add_uint("udp.port", MEP_DATA_PORT, data_handle);
}
