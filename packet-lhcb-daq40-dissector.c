#include "config.h"
#include <epan/packet.h>
#define FOO_PORT 1234

static int proto_foo = -1;

static void dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
}

void proto_register_foo(void)
{
    proto_foo = proto_register_protocol (
        "FOO Protocol", /* name       */
        "FOO",      /* short name */
        "foo"       /* abbrev     */
        );
}

void proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}
