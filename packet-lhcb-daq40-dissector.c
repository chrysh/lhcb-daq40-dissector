#include "config.h"
#include <epan/packet.h>
#define MEP_PORT 1234

static int proto_mep = -1;

static void dissect_mep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
}

void proto_register_mep(void)
{
    proto_mep = proto_register_protocol (
        "MEP Protocol", /* name       */
        "MEP",      /* short name */
        "mep"       /* abbrev     */
        );
}

void proto_reg_handoff_mep(void)
{
    static dissector_handle_t mep_handle;

    mep_handle = create_dissector_handle(dissect_mep, proto_mep);
    dissector_add_uint("udp.port", MEP_PORT, mep_handle);
}
