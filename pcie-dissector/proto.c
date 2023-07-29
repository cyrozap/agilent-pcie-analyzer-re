// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto.c - PCIe dissector for Wireshark.
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

#include <epan/packet.h>
#include <epan/proto.h>

#include "proto.h"


static const int PCIE_CAPTURE_HEADER_SIZE = 20;


static int PROTO_PCIE = -1;
static int PROTO_PCIE_DLLP = -1;
static int PROTO_PCIE_TLP = -1;

static int HF_PCIE_RECORD = -1;
static int HF_PCIE_TIMESTAMP_NS = -1;
static int HF_PCIE_UNK = -1;
static int HF_PCIE_DATA_VALID = -1;
static int HF_PCIE_DATA_VALID_COUNT = -1;
static int HF_PCIE_SYMBOL_ERROR = -1;
static int HF_PCIE_DISPARITY_ERROR = -1;
static int HF_PCIE_DIRECTION = -1;

static int HF_PCIE_DLLP_START_TAG = -1;
static int HF_PCIE_DLLP_RESERVED = -1;
static int HF_PCIE_DLLP_SEQ = -1;
static int HF_PCIE_DLLP_LCRC = -1;
static int HF_PCIE_DLLP_END_TAG = -1;

static hf_register_info HF_PCIE[] = {
    { &HF_PCIE_RECORD,
        { "Record Number", "pcie.record",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TIMESTAMP_NS,
        { "Timestamp (ns)", "pcie.timestamp_ns",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_UNK,
        { "Unknown", "pcie.unk",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_DATA_VALID,
        { "Data Valid", "pcie.data_valid",
        FT_BOOLEAN, 16,
        NULL, 0x8000,
        NULL, HFILL }
    },
    { &HF_PCIE_DATA_VALID_COUNT,
        { "Data Valid Count", "pcie.data_valid_count",
        FT_UINT16, BASE_DEC,
        NULL, 0x7FFF,
        NULL, HFILL }
    },
    { &HF_PCIE_SYMBOL_ERROR,
        { "Symbol Error", "pcie.symbol_error",
        FT_BOOLEAN, 32,
        NULL, 0x00000008,
        NULL, HFILL }
    },
    { &HF_PCIE_DISPARITY_ERROR,
        { "Disparity Error", "pcie.disparity_error",
        FT_BOOLEAN, 32,
        NULL, 0x00000800,
        NULL, HFILL }
    },
    { &HF_PCIE_DIRECTION,
        { "Direction", "pcie.direction",
        FT_BOOLEAN, 32,
        NULL, 0x10000000,
        NULL, HFILL }
    },
};

static hf_register_info HF_PCIE_DLLP[] = {
    { &HF_PCIE_DLLP_START_TAG,
        { "Start Tag", "pcie.dllp.start_tag",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_DLLP_RESERVED,
        { "Reserved", "pcie.dllp.reserved",
        FT_UINT16, BASE_HEX,
        NULL, 0xF000,
        NULL, HFILL }
    },
    { &HF_PCIE_DLLP_SEQ,
        { "Sequence Number", "pcie.dllp.seq",
        FT_UINT16, BASE_DEC,
        NULL, 0x0FFF,
        NULL, HFILL }
    },
    { &HF_PCIE_DLLP_LCRC,
        { "LCRC", "pcie.dllp.lcrc",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_DLLP_END_TAG,
        { "End Tag", "pcie.dllp.end_tag",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static int ETT_PCIE = -1;
static int ETT_PCIE_DLLP = -1;
static int * const ETT[] = {
        &ETT_PCIE,
        &ETT_PCIE_DLLP,
};


static int dissect_pcie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_item * pcie_tree_item = proto_tree_add_item(tree, PROTO_PCIE, tvb, 0, PCIE_CAPTURE_HEADER_SIZE, ENC_NA);
    proto_tree * pcie_tree = proto_item_add_subtree(pcie_tree_item, ETT_PCIE);
    proto_tree_add_item(pcie_tree, HF_PCIE_RECORD, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pcie_tree, HF_PCIE_TIMESTAMP_NS, tvb, 4, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pcie_tree, HF_PCIE_UNK, tvb, 12, 2, ENC_LITTLE_ENDIAN);

    gboolean data_valid = false;
    proto_tree_add_item_ret_boolean(pcie_tree, HF_PCIE_DATA_VALID, tvb, 14, 2, ENC_LITTLE_ENDIAN, &data_valid);

    uint32_t data_valid_count = 0;
    proto_tree_add_item_ret_uint(pcie_tree, HF_PCIE_DATA_VALID_COUNT, tvb, 14, 2, ENC_LITTLE_ENDIAN, &data_valid_count);

    proto_tree_add_item(pcie_tree, HF_PCIE_SYMBOL_ERROR, tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pcie_tree, HF_PCIE_DISPARITY_ERROR, tvb, 16, 4, ENC_LITTLE_ENDIAN);

    gboolean direction = 0;
    proto_tree_add_item_ret_boolean(pcie_tree, HF_PCIE_DIRECTION, tvb, 16, 4, ENC_LITTLE_ENDIAN, &direction);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCIe");

    if (direction) {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "Downstream Device");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "Upstream Device");
    } else {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "Upstream Device");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "Downstream Device");
    }

    if ((!data_valid) || (data_valid_count < 1))  {
        return tvb_captured_length(tvb);
    }

    tvbuff_t * dllp_tvb = tvb_new_subset_length_caplen(tvb, PCIE_CAPTURE_HEADER_SIZE, data_valid_count, data_valid_count);
    proto_item * dllp_tree_item = proto_tree_add_item(tree, PROTO_PCIE_DLLP, dllp_tvb, 0, data_valid_count, ENC_NA);
    proto_tree * dllp_tree = proto_item_add_subtree(dllp_tree_item, ETT_PCIE_DLLP);

    uint32_t start_tag = 0;
    proto_tree_add_item_ret_uint(dllp_tree, HF_PCIE_DLLP_START_TAG, dllp_tvb, 0, 1, ENC_BIG_ENDIAN, &start_tag);

    if (start_tag != 0xfb) {
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item(dllp_tree, HF_PCIE_DLLP_RESERVED, dllp_tvb, 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dllp_tree, HF_PCIE_DLLP_SEQ, dllp_tvb, 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dllp_tree, HF_PCIE_DLLP_LCRC, dllp_tvb, data_valid_count-5, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(dllp_tree, HF_PCIE_DLLP_END_TAG, dllp_tvb, data_valid_count-1, 1, ENC_BIG_ENDIAN);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCIe DLLP");

    return tvb_captured_length(tvb);
}

static void proto_register_pcie_capture() {
    PROTO_PCIE = proto_register_protocol(
        "PCI Express Capture",
        "PCIe",
        "pcie"
    );

    proto_register_field_array(PROTO_PCIE, HF_PCIE, array_length(HF_PCIE));
}

static void proto_register_pcie_dllp() {
    PROTO_PCIE_DLLP = proto_register_protocol(
        "PCI Express Data Link Layer Packet",
        "PCIe DLLP",
        "pcie.dllp"
    );

    proto_register_field_array(PROTO_PCIE_DLLP, HF_PCIE_DLLP, array_length(HF_PCIE_DLLP));
}

static void proto_register_pcie_tlp() {
    PROTO_PCIE_TLP = proto_register_protocol(
        "PCI Express Transaction Layer Packet",
        "PCIe TLP",
        "pcie.tlp"
    );
}

void proto_register_pcie() {
    // PCIe Capture
    proto_register_pcie_capture();

    // PCIe DLLP
    proto_register_pcie_dllp();

    // PCIe TLP
    proto_register_pcie_tlp();

    proto_register_subtree_array(ETT, array_length(ETT));
}

void proto_reg_handoff_pcie() {
    dissector_handle_t pcie_handle = create_dissector_handle(dissect_pcie, PROTO_PCIE);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER11, pcie_handle);
}
