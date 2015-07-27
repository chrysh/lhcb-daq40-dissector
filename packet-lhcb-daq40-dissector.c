#include "config.h"
#include <epan/packet.h>
#include <stdio.h>
#define MEP_PORT 1234

static int proto_mep = -1;
static int hf_mep_pdu_type = -1;
static int hf_mep_seqno = -1;

static gint ett_mep = -1;


static void dissect_mep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *pi = NULL;
    proto_tree *mep_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEP");
    printf("*** Dissect MEP \n");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    if (tree) {     /* return details */
        pi = proto_tree_add_item(tree, proto_mep, tvb, 0, -1, ENC_NA);
        mep_tree = proto_item_add_subtree(pi, ett_mep);
        proto_tree_add_item(mep_tree, hf_mep_pdu_type, tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mep_tree, hf_mep_seqno, tvb, 1, 1, ENC_BIG_ENDIAN);
    }
}

void proto_register_mep(void)
{
    /* protocol subtree array*/
    static gint *ett[] = {
        &ett_mep
    };

    static const value_string pkt_type_names[] = {
        {0x41, "Received an A"},
        {0x42, "Received something else"},
        {0, NULL},
    };

    static hf_register_info hf[] = {
        { &hf_mep_seqno,
            { "MEP Sequence number", "mep.seqno",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "seqno", HFILL }
        },
        { &hf_mep_pdu_type,
            { "MEP PDU Type", "mep.type",
            FT_UINT8, BASE_HEX,
            VALS(pkt_type_names), 0x0,
            "pdu type", HFILL }
        },

    };

    proto_mep = proto_register_protocol (
        "MEP Protocol", /* name       */
        "MEP",      /* short name */
        "mep"       /* abbrev     */
        );


    printf("*** Registering MEP protocol, array length: %d \n", array_length(hf));

    proto_register_field_array(proto_mep, hf, array_length(hf));
    printf("*** Halfway \n");
    proto_register_subtree_array(ett, array_length(ett));
    printf("*** DONE \n");
}

void proto_reg_handoff_mep(void)
{
    static dissector_handle_t mep_handle;
    printf("*** MEP protocol handoff\n");

    mep_handle = create_dissector_handle(dissect_mep, proto_mep);
    dissector_add_uint("udp.port", MEP_PORT, mep_handle);
}
