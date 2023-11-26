// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_nettlp.c - NetTLP dissector for Wireshark.
 *  Copyright (C) 2023  Forest Crossman <cyrozap@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <wsutil/crc32.h>

#include "proto_nettlp.h"


static const range_t NETTLP_PORT_RANGE = {
    .nranges = 1,
    .ranges = {
        { .low = 12288, .high = 20479 },
    },
};

static dissector_handle_t NETTLP_HANDLE = NULL;
static dissector_handle_t PCIE_TLP_HANDLE = NULL;

static int PROTO_NETTLP = -1;

static int HF_NETTLP_SEQUENCE = -1;
static int HF_NETTLP_TIMESTAMP = -1;

static hf_register_info HF_NETTLP[] = {
    { &HF_NETTLP_SEQUENCE,
        { "Sequence", "nettlp.sequence",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_NETTLP_TIMESTAMP,
        { "Timestamp", "nettlp.timestamp",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static int ETT_NETTLP = -1;
static int * const ETT[] = {
    &ETT_NETTLP,
};

static int dissect_nettlp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetTLP");

    proto_item * nettlp_tree_item = proto_tree_add_item(tree, PROTO_NETTLP, tvb, 0, 6, ENC_NA);
    proto_tree * nettlp_tree = proto_item_add_subtree(nettlp_tree_item, ETT_NETTLP);

    proto_tree_add_item(nettlp_tree, HF_NETTLP_SEQUENCE, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(nettlp_tree, HF_NETTLP_TIMESTAMP, tvb, 2, 4, ENC_BIG_ENDIAN);

    call_dissector(PCIE_TLP_HANDLE, tvb_new_subset_remaining(tvb, 6), pinfo, tree);

    return tvb_captured_length(tvb);
}

void proto_register_nettlp() {
    proto_register_subtree_array(ETT, array_length(ETT));

    PROTO_NETTLP = proto_register_protocol(
        "NetTLP",
        "NetTLP",
        "nettlp"
    );

    proto_register_field_array(PROTO_NETTLP, HF_NETTLP, array_length(HF_NETTLP));

    NETTLP_HANDLE = register_dissector("nettlp", dissect_nettlp, PROTO_NETTLP);

    PCIE_TLP_HANDLE = find_dissector_add_dependency("pcie.tlp", PROTO_NETTLP);
}

void proto_reg_handoff_nettlp() {
    dissector_add_uint_range("udp.port", (range_t *)&NETTLP_PORT_RANGE, NETTLP_HANDLE);
    dissector_add_for_decode_as("udp.port", NETTLP_HANDLE);
}
