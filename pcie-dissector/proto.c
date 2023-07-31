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

#include <stdint.h>

#include <epan/packet.h>
#include <epan/proto.h>

#include "proto.h"


static const int PCIE_CAPTURE_HEADER_SIZE = 20;

static const true_false_string tfs_direction = { "Upstream", "Downstream" };

// 8b/10b Special Character Symbols
static const uint32_t K_28_0 = 0x1C;
static const uint32_t K_28_1 = 0x3C;
static const uint32_t K_28_2 = 0x5C;
static const uint32_t K_28_3 = 0x7C;
static const uint32_t K_28_4 = 0x9C;
static const uint32_t K_28_5 = 0xBC;
static const uint32_t K_28_6 = 0xDC;
static const uint32_t K_28_7 = 0xFC;
static const uint32_t K_23_7 = 0xF7;
static const uint32_t K_27_7 = 0xFB;
static const uint32_t K_29_7 = 0xFD;
static const uint32_t K_30_7 = 0xFE;

static const value_string K_SYMBOLS[] = {
    { K_28_5, "COM (Comma)" },
    { K_27_7, "STP (Start TLP)" },
    { K_28_2, "SDP (Start DLLP)" },
    { K_29_7, "END (End)" },
    { K_30_7, "EDB (EnD Bad)" },
    { K_23_7, "PAD (Pad)" },
    { K_28_0, "SKP (Skip)" },
    { K_28_1, "FTS (Fast Training Sequence)" },
    { K_28_3, "IDL (Idle)" },
    { K_28_4, "K28.4 (Reserved)" },
    { K_28_6, "K28.6 (Reserved)" },
    { K_28_7, "EIE (Electrical Idle Exit)"},
    { 0, NULL },
};

static const value_string TLP_FMT_TYPE[] = {
    { 0b00000000, "Memory Read Request (3 DW header)" },
    { 0b00100000, "Memory Read Request (4 DW header)" },
    { 0b00000001, "Memory Read Request-Locked (3 DW header)" },
    { 0b00100001, "Memory Read Request-Locked (4 DW header)" },
    { 0b01000000, "Memory Write Request (3 DW header)" },
    { 0b01100000, "Memory Write Request (4 DW header)" },
    { 0b00000010, "I/O Read Request" },
    { 0b01000010, "I/O Write Request" },
    { 0b00000100, "Configuration Read Type 0" },
    { 0b01000100, "Configuration Write Type 0" },
    { 0b00000101, "Configuration Read Type 1" },
    { 0b01000101, "Configuration Write Type 1" },
    { 0b00110000, "Message Request (Routed to Root Complex)" },
    { 0b00110001, "Message Request (Routed by Address)" },
    { 0b00110010, "Message Request (Routed by ID)" },
    { 0b00110011, "Message Request (Broadcast from Root Complex)" },
    { 0b00110100, "Message Request (Local - Terminate at Receiver)" },
    { 0b00110101, "Message Request (Gathered and routed to Root Complex)" },
    { 0b00110110, "Message Request (Reserved - Terminate at Receiver)" },
    { 0b00110111, "Message Request (Reserved - Terminate at Receiver)" },
    { 0b01110000, "Message Request with data payload (Routed to Root Complex)" },
    { 0b01110001, "Message Request with data payload (Routed by Address)" },
    { 0b01110010, "Message Request with data payload (Routed by ID)" },
    { 0b01110011, "Message Request with data payload (Broadcast from Root Complex)" },
    { 0b01110100, "Message Request with data payload (Local - Terminate at Receiver)" },
    { 0b01110101, "Message Request with data payload (Gathered and routed to Root Complex)" },
    { 0b01110110, "Message Request with data payload (Reserved - Terminate at Receiver)" },
    { 0b01110111, "Message Request with data payload (Reserved - Terminate at Receiver)" },
    { 0b00001010, "Completion without Data" },
    { 0b01001010, "Completion with Data" },
    { 0b00001011, "Completion for Locked Memory Read without Data" },
    { 0b01001011, "Completion for Locked Memory Read" },
    { 0b01001100, "Fetch and Add AtomicOp Request (3 DW header)" },
    { 0b01101100, "Fetch and Add AtomicOp Request (4 DW header)" },
    { 0b01001101, "Unconditional Swap AtomicOp Request (3 DW header)" },
    { 0b01101101, "Unconditional Swap AtomicOp Request (4 DW header)" },
    { 0b01001110, "Compare and Swap AtomicOp Request (3 DW header)" },
    { 0b01101110, "Compare and Swap AtomicOp Request (4 DW header)" },
    { 0, NULL },
};

static const value_string TLP_FMT[] = {
    { 0b000, "3 DW header, no data" },
    { 0b001, "4 DW header, no data" },
    { 0b010, "3 DW header, with data" },
    { 0b011, "4 DW header, with data" },
    { 0b100, "TLP Prefix" },
    { 0, NULL },
};

static const value_string TLP_TYPE[] = {
    { 0b00000, "Memory Request" },
    { 0b00001, "Memory Request-Locked" },
    { 0b00010, "I/O Request" },
    { 0b00100, "Configuration Request Type 0" },
    { 0b00101, "Configuration Request Type 1" },
    { 0b10000, "Message Request (Routed to Root Complex)" },
    { 0b10001, "Message Request (Routed by Address)" },
    { 0b10010, "Message Request (Routed by ID)" },
    { 0b10011, "Message Request (Broadcast from Root Complex)" },
    { 0b10100, "Message Request (Local - Terminate at Receiver)" },
    { 0b10101, "Message Request (Gathered and routed to Root Complex)" },
    { 0b10110, "Message Request (Reserved - Terminate at Receiver)" },
    { 0b10111, "Message Request (Reserved - Terminate at Receiver)" },
    { 0b01010, "Completion" },
    { 0b01011, "Completion for Locked Memory Read" },
    { 0b01100, "Fetch and Add AtomicOp Request" },
    { 0b01101, "Unconditional Swap AtomicOp Request" },
    { 0b01110, "Compare and Swap AtomicOp Request" },
    { 0, NULL },
};

static const value_string TLP_CPL_STATUS[] = {
    { 0b000, "Successful Completion (SC)" },
    { 0b001, "Unsupported Request (UR)" },
    { 0b010, "Configuration Request Retry Status (CRS)" },
    { 0b100, "Completer Abort (CA)" },
    { 0, NULL },
};

static dissector_handle_t PCIE_HANDLE = NULL;

static int PROTO_PCIE = -1;
static int PROTO_PCIE_FRAME = -1;
static int PROTO_PCIE_TLP = -1;

static int HF_PCIE_RECORD = -1;
static int HF_PCIE_TIMESTAMP_NS = -1;
static int HF_PCIE_UNK = -1;
static int HF_PCIE_DATA_VALID = -1;
static int HF_PCIE_DATA_VALID_COUNT = -1;
static int HF_PCIE_SYMBOL_ERROR = -1;
static int HF_PCIE_DISPARITY_ERROR = -1;
static int HF_PCIE_DIRECTION = -1;

static int HF_PCIE_FRAME_START_TAG = -1;
static int HF_PCIE_FRAME_TLP_RESERVED = -1;
static int HF_PCIE_FRAME_TLP_SEQ = -1;
static int HF_PCIE_FRAME_TLP_LCRC = -1;
static int HF_PCIE_FRAME_END_TAG = -1;

static int HF_PCIE_TLP_DW0 = -1;
static int HF_PCIE_TLP_FMT_TYPE = -1;
static int HF_PCIE_TLP_FMT = -1;
static int HF_PCIE_TLP_TYPE = -1;
static int HF_PCIE_TLP_T9 = -1;
static int HF_PCIE_TLP_TC = -1;
static int HF_PCIE_TLP_T8 = -1;
static int HF_PCIE_TLP_ATTR2 = -1;
static int HF_PCIE_TLP_LN = -1;
static int HF_PCIE_TLP_TH = -1;
static int HF_PCIE_TLP_TD = -1;
static int HF_PCIE_TLP_EP = -1;
static int HF_PCIE_TLP_ATTR10 = -1;
static int HF_PCIE_TLP_AT = -1;
static int HF_PCIE_TLP_LENGTH = -1;

static int HF_PCIE_TLP_REQ_ID = -1;
static int HF_PCIE_TLP_REQ_BUS = -1;
static int HF_PCIE_TLP_REQ_DEV = -1;
static int HF_PCIE_TLP_REQ_FUN = -1;
static int HF_PCIE_TLP_TAG = -1;
static int HF_PCIE_TLP_LAST_DW_BE = -1;
static int HF_PCIE_TLP_FIRST_DW_BE = -1;
static int HF_PCIE_TLP_ADDR_32 = -1;
static int HF_PCIE_TLP_ADDR_64 = -1;
static int HF_PCIE_TLP_CPL_ID = -1;
static int HF_PCIE_TLP_CPL_BUS = -1;
static int HF_PCIE_TLP_CPL_DEV = -1;
static int HF_PCIE_TLP_CPL_FUN = -1;
static int HF_PCIE_TLP_REG = -1;
static int HF_PCIE_TLP_CPL_STATUS = -1;
static int HF_PCIE_TLP_CPL_BCM = -1;
static int HF_PCIE_TLP_CPL_BYTE_COUNT = -1;
static int HF_PCIE_TLP_CPL_LOWER_ADDR = -1;
static int HF_PCIE_TLP_ECRC = -1;

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
        TFS(&tfs_direction), 0x10000000,
        NULL, HFILL }
    },
};

static hf_register_info HF_PCIE_FRAME[] = {
    { &HF_PCIE_FRAME_START_TAG,
        { "Start Tag", "pcie.frame.start_tag",
        FT_UINT8, BASE_HEX,
        VALS(K_SYMBOLS), 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_FRAME_TLP_RESERVED,
        { "TLP Reserved", "pcie.frame.tlp.reserved",
        FT_UINT16, BASE_HEX,
        NULL, 0xF000,
        NULL, HFILL }
    },
    { &HF_PCIE_FRAME_TLP_SEQ,
        { "TLP Sequence Number", "pcie.frame.tlp.seq",
        FT_UINT16, BASE_DEC,
        NULL, 0x0FFF,
        NULL, HFILL }
    },
    { &HF_PCIE_FRAME_TLP_LCRC,
        { "TLP LCRC", "pcie.frame.tlp.lcrc",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_FRAME_END_TAG,
        { "End Tag", "pcie.frame.end_tag",
        FT_UINT8, BASE_HEX,
        VALS(K_SYMBOLS), 0x0,
        NULL, HFILL }
    },
};

static hf_register_info HF_PCIE_TLP[] = {
    { &HF_PCIE_TLP_DW0,
        { "TLP DW 0", "pcie.tlp.dw0",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_FMT_TYPE,
        { "Fmt Type", "pcie.tlp.fmt_type",
        FT_UINT8, BASE_HEX,
        VALS(TLP_FMT_TYPE), 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_FMT,
        { "Fmt", "pcie.tlp.fmt",
        FT_UINT8, BASE_HEX,
        VALS(TLP_FMT), 0xE0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_TYPE,
        { "Type", "pcie.tlp.type",
        FT_UINT8, BASE_HEX,
        VALS(TLP_TYPE), 0x1F,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_T9,
        { "Tag[9]", "pcie.tlp.t9",
        FT_UINT24, BASE_DEC,
        NULL, 0b1 << 23,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_TC,
        { "Traffic Class", "pcie.tlp.tc",
        FT_UINT24, BASE_HEX,
        NULL, 0b111 << 20,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_T8,
        { "Tag[8]", "pcie.tlp.t8",
        FT_UINT24, BASE_DEC,
        NULL, 0b1 << 19,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ATTR2,
        { "Attr[2]", "pcie.tlp.attr2",
        FT_UINT24, BASE_DEC,
        NULL, 0b1 << 18,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_LN,
        { "Lightweight Notification", "pcie.tlp.ln",
        FT_BOOLEAN, 24,
        NULL, 0b1 << 17,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_TH,
        { "TLP Hints", "pcie.tlp.th",
        FT_BOOLEAN, 24,
        NULL, 0b1 << 16,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_TD,
        { "TLP Digest", "pcie.tlp.td",
        FT_BOOLEAN, 24,
        NULL, 0b1 << 15,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_EP,
        { "Error Poisoned", "pcie.tlp.ep",
        FT_BOOLEAN, 24,
        NULL, 0b1 << 14,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ATTR10,
        { "Attr[1:0]", "pcie.tlp.attr10",
        FT_UINT24, BASE_HEX,
        NULL, 0b11 << 12,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_AT,
        { "Address Type", "pcie.tlp.at",
        FT_UINT24, BASE_HEX,
        NULL, 0b11 << 10,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_LENGTH,
        { "Payload Length", "pcie.tlp.len",
        FT_UINT24, BASE_DEC,
        NULL, 0x3FF,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_REQ_ID,
        { "Requester ID", "pcie.tlp.req",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_REQ_BUS,
        { "Requester Bus", "pcie.tlp.req.bus",
        FT_UINT16, BASE_HEX,
        NULL, 0xFF00,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_REQ_DEV,
        { "Requester Device", "pcie.tlp.req.dev",
        FT_UINT16, BASE_HEX,
        NULL, 0x00F8,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_REQ_FUN,
        { "Requester Function", "pcie.tlp.req.fun",
        FT_UINT16, BASE_DEC,
        NULL, 0x0007,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_TAG,
        { "Tag", "pcie.tlp.tag",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_LAST_DW_BE,
        { "Last DW BE", "pcie.tlp.last_dw_be",
        FT_UINT8, BASE_HEX,
        NULL, 0xF0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_FIRST_DW_BE,
        { "First DW BE", "pcie.tlp.first_dw_be",
        FT_UINT8, BASE_HEX,
        NULL, 0x0F,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ADDR_32,
        { "Address", "pcie.tlp.addr",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ADDR_64,
        { "Address", "pcie.tlp.addr",
        FT_UINT64, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_ID,
        { "Completer ID", "pcie.tlp.cpl",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_BUS,
        { "Completer Bus", "pcie.tlp.cpl.bus",
        FT_UINT16, BASE_HEX,
        NULL, 0xFF00,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_DEV,
        { "Completer Device", "pcie.tlp.cpl.dev",
        FT_UINT16, BASE_HEX,
        NULL, 0x00F8,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_FUN,
        { "Completer Function", "pcie.tlp.cpl.fun",
        FT_UINT16, BASE_DEC,
        NULL, 0x0007,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_REG,
        { "Register Number", "pcie.tlp.reg",
        FT_UINT16, BASE_HEX,
        NULL, 0x0FFC,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_STATUS,
        { "Completion Status", "pcie.tlp.cpl.status",
        FT_UINT16, BASE_HEX,
        VALS(TLP_CPL_STATUS), 0b111 << 13,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_BCM,
        { "Byte Count Modified", "pcie.tlp.cpl.bcm",
        FT_BOOLEAN, 16,
        NULL, 0b1 << 12,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_BYTE_COUNT,
        { "Byte Count", "pcie.tlp.cpl.byte_count",
        FT_UINT16, BASE_DEC,
        NULL, 0x0FFF,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_LOWER_ADDR,
        { "Lower Address", "pcie.tlp.cpl.lower_addr",
        FT_UINT8, BASE_HEX,
        NULL, 0x7F,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ECRC,
        { "End-to-end CRC", "pcie.tlp.ecrc",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static int ETT_PCIE = -1;
static int ETT_PCIE_FRAME = -1;
static int ETT_PCIE_TLP = -1;
static int ETT_PCIE_TLP_DW0 = -1;
static int ETT_PCIE_TLP_FMT_TYPE = -1;
static int ETT_PCIE_TLP_REQ_ID = -1;
static int ETT_PCIE_TLP_CPL_ID = -1;
static int * const ETT[] = {
        &ETT_PCIE,
        &ETT_PCIE_FRAME,
        &ETT_PCIE_TLP,
        &ETT_PCIE_TLP_DW0,
        &ETT_PCIE_TLP_FMT_TYPE,
        &ETT_PCIE_TLP_REQ_ID,
        &ETT_PCIE_TLP_CPL_ID,
};


static void dissect_pcie_frame_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, gboolean direction);
static void dissect_pcie_tlp_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, gboolean direction);
static void dissect_tlp_mem_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, bool addr64);
static void dissect_tlp_cfg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static void dissect_tlp_cpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

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

    tvbuff_t * frame_tvb = tvb_new_subset_length_caplen(tvb, PCIE_CAPTURE_HEADER_SIZE, data_valid_count, data_valid_count);
    dissect_pcie_frame_internal(frame_tvb, pinfo, tree, data, direction);

    return tvb_captured_length(tvb);
}

static void dissect_pcie_frame_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, gboolean direction) {
    uint32_t frame_len = tvb_reported_length(tvb);

    proto_item * frame_tree_item = proto_tree_add_item(tree, PROTO_PCIE_FRAME, tvb, 0, frame_len, ENC_NA);
    proto_tree * frame_tree = proto_item_add_subtree(frame_tree_item, ETT_PCIE_FRAME);

    uint32_t start_tag = 0;
    proto_tree_add_item_ret_uint(frame_tree, HF_PCIE_FRAME_START_TAG, tvb, 0, 1, ENC_BIG_ENDIAN, &start_tag);

    switch (start_tag) {
        case K_27_7:
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCIe TLP");
            proto_tree_add_item(frame_tree, HF_PCIE_FRAME_TLP_RESERVED, tvb, 1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(frame_tree, HF_PCIE_FRAME_TLP_SEQ, tvb, 1, 2, ENC_BIG_ENDIAN);

            // TODO: Dissect TLP first, then calculate offset of LCRC and end tag depending on how many bytes were in the TLP.
            proto_tree_add_item(frame_tree, HF_PCIE_FRAME_TLP_LCRC, tvb, frame_len-5, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(frame_tree, HF_PCIE_FRAME_END_TAG, tvb, frame_len-1, 1, ENC_BIG_ENDIAN);

            uint32_t tlp_len = frame_len-3-5;
            tvbuff_t * tlp_tvb = tvb_new_subset_length_caplen(tvb, 3, tlp_len, tlp_len);
            dissect_pcie_tlp_internal(tlp_tvb, pinfo, tree, data, direction);

            break;
        case K_28_2:
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCIe DLLP");
            proto_tree_add_item(frame_tree, HF_PCIE_FRAME_END_TAG, tvb, frame_len-1, 1, ENC_BIG_ENDIAN);
            break;
        default:
            break;
    }
}

static void dissect_pcie_tlp_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, gboolean direction) {
    uint32_t tlp_len = tvb_reported_length(tvb);
    proto_item * tlp_tree_item = proto_tree_add_item(tree, PROTO_PCIE_TLP, tvb, 0, tlp_len, ENC_NA);
    proto_tree * tlp_tree = proto_item_add_subtree(tlp_tree_item, ETT_PCIE_TLP);

    proto_item * dw0_tree_item = proto_tree_add_item(tlp_tree, HF_PCIE_TLP_DW0, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree * dw0_tree = proto_item_add_subtree(dw0_tree_item, ETT_PCIE_TLP_DW0);

    proto_item * fmt_type_item = proto_tree_add_item(dw0_tree, HF_PCIE_TLP_FMT_TYPE, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree * fmt_type_tree = proto_item_add_subtree(fmt_type_item, ETT_PCIE_TLP_FMT_TYPE);

    uint32_t tlp_fmt = 0;
    proto_tree_add_item_ret_uint(fmt_type_tree, HF_PCIE_TLP_FMT, tvb, 0, 1, ENC_BIG_ENDIAN, &tlp_fmt);

    if (tlp_fmt >= 0b100) {
        // TODO: Add support for TLP Prefixes.
        return;
    }

    uint32_t tlp_type = 0;
    proto_tree_add_item_ret_uint(fmt_type_tree, HF_PCIE_TLP_TYPE, tvb, 0, 1, ENC_BIG_ENDIAN, &tlp_type);

    // Fields Present in All TLP Headers
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_T9, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_TC, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_T8, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_ATTR2, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_LN, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_TH, tvb, 1, 3, ENC_BIG_ENDIAN);
    gboolean tlp_digest = 0;
    proto_tree_add_item_ret_boolean(dw0_tree, HF_PCIE_TLP_TD, tvb, 1, 3, ENC_BIG_ENDIAN, &tlp_digest);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_EP, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_ATTR10, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_AT, tvb, 1, 3, ENC_BIG_ENDIAN);
    uint32_t payload_len = 0;
    proto_tree_add_item_ret_uint(dw0_tree, HF_PCIE_TLP_LENGTH, tvb, 1, 3, ENC_BIG_ENDIAN, &payload_len);

    switch (tlp_type) {
        case 0b00000:
            dissect_tlp_mem_req(tvb, pinfo, tlp_tree, data, (tlp_fmt & 0b001) != 0);
            break;
        case 0b00100:
        case 0b00101:
            dissect_tlp_cfg_req(tvb, pinfo, tlp_tree, data);
            break;
        case 0b01010:
            dissect_tlp_cpl(tvb, pinfo, tlp_tree, data);
            break;
        default:
            break;
    }

    if (tlp_digest) {
        int ecrc_dw_offset = 3 + (tlp_fmt & 0b001);
        if (tlp_fmt & 0b010) {
            ecrc_dw_offset += payload_len;
        }
        proto_tree_add_item(tlp_tree, HF_PCIE_TLP_ECRC, tvb, 4*ecrc_dw_offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_tlp_req_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_item * req_id_item = proto_tree_add_item(tree, HF_PCIE_TLP_REQ_ID, tvb, 4, 2, ENC_BIG_ENDIAN);
    proto_tree * req_id_tree = proto_item_add_subtree(req_id_item, ETT_PCIE_TLP_REQ_ID);
    uint32_t req_bus = 0;
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_BUS, tvb, 4, 2, ENC_BIG_ENDIAN, &req_bus);
    uint32_t req_dev = 0;
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_DEV, tvb, 4, 2, ENC_BIG_ENDIAN, &req_dev);
    uint32_t req_fun = 0;
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_FUN, tvb, 4, 2, ENC_BIG_ENDIAN, &req_fun);

    col_clear(pinfo->cinfo, COL_DEF_SRC);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%02x:%02x.%x", req_bus, req_dev, req_fun);

    proto_tree_add_item(tree, HF_PCIE_TLP_TAG, tvb, 6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, HF_PCIE_TLP_LAST_DW_BE, tvb, 7, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, HF_PCIE_TLP_FIRST_DW_BE, tvb, 7, 1, ENC_BIG_ENDIAN);
}

static void dissect_tlp_mem_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, bool addr64) {
    dissect_tlp_req_header(tvb, pinfo, tree, data);

    if (addr64) {
        uint64_t addr = 0;
        proto_tree_add_item_ret_uint64(tree, HF_PCIE_TLP_ADDR_64, tvb, 8, 8, ENC_BIG_ENDIAN, &addr);

        col_clear(pinfo->cinfo, COL_DEF_DST);
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%016lx", addr);
    } else {
        uint32_t addr = 0;
        proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_ADDR_32, tvb, 8, 4, ENC_BIG_ENDIAN, &addr);

        col_clear(pinfo->cinfo, COL_DEF_DST);
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08x", addr);
    }
}

static void dissect_tlp_cfg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    dissect_tlp_req_header(tvb, pinfo, tree, data);

    proto_item * cpl_id_item = proto_tree_add_item(tree, HF_PCIE_TLP_CPL_ID, tvb, 8, 2, ENC_BIG_ENDIAN);
    proto_tree * cpl_id_tree = proto_item_add_subtree(cpl_id_item, ETT_PCIE_TLP_CPL_ID);
    uint32_t cpl_bus = 0;
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_BUS, tvb, 8, 2, ENC_BIG_ENDIAN, &cpl_bus);
    uint32_t cpl_dev = 0;
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_DEV, tvb, 8, 2, ENC_BIG_ENDIAN, &cpl_dev);
    uint32_t cpl_fun = 0;
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_FUN, tvb, 8, 2, ENC_BIG_ENDIAN, &cpl_fun);

    col_clear(pinfo->cinfo, COL_DEF_DST);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%02x:%02x.%x", cpl_bus, cpl_dev, cpl_fun);

    proto_tree_add_item(tree, HF_PCIE_TLP_REG, tvb, 10, 2, ENC_BIG_ENDIAN);
}

static void dissect_tlp_cpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_item * cpl_id_item = proto_tree_add_item(tree, HF_PCIE_TLP_CPL_ID, tvb, 4, 2, ENC_BIG_ENDIAN);
    proto_tree * cpl_id_tree = proto_item_add_subtree(cpl_id_item, ETT_PCIE_TLP_CPL_ID);
    uint32_t cpl_bus = 0;
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_BUS, tvb, 4, 2, ENC_BIG_ENDIAN, &cpl_bus);
    uint32_t cpl_dev = 0;
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_DEV, tvb, 4, 2, ENC_BIG_ENDIAN, &cpl_dev);
    uint32_t cpl_fun = 0;
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_FUN, tvb, 4, 2, ENC_BIG_ENDIAN, &cpl_fun);

    col_clear(pinfo->cinfo, COL_DEF_SRC);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%02x:%02x.%x", cpl_bus, cpl_dev, cpl_fun);

    proto_tree_add_item(tree, HF_PCIE_TLP_CPL_STATUS, tvb, 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, HF_PCIE_TLP_CPL_BCM, tvb, 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, HF_PCIE_TLP_CPL_BYTE_COUNT, tvb, 6, 2, ENC_BIG_ENDIAN);

    proto_item * req_id_item = proto_tree_add_item(tree, HF_PCIE_TLP_REQ_ID, tvb, 8, 2, ENC_BIG_ENDIAN);
    proto_tree * req_id_tree = proto_item_add_subtree(req_id_item, ETT_PCIE_TLP_REQ_ID);
    uint32_t req_bus = 0;
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_BUS, tvb, 8, 2, ENC_BIG_ENDIAN, &req_bus);
    uint32_t req_dev = 0;
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_DEV, tvb, 8, 2, ENC_BIG_ENDIAN, &req_dev);
    uint32_t req_fun = 0;
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_FUN, tvb, 8, 2, ENC_BIG_ENDIAN, &req_fun);

    col_clear(pinfo->cinfo, COL_DEF_DST);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%02x:%02x.%x", req_bus, req_dev, req_fun);

    proto_tree_add_item(tree, HF_PCIE_TLP_TAG, tvb, 10, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, HF_PCIE_TLP_CPL_LOWER_ADDR, tvb, 11, 1, ENC_BIG_ENDIAN);
}

static void proto_register_pcie_capture() {
    PROTO_PCIE = proto_register_protocol(
        "PCI Express Capture",
        "PCIe",
        "pcie"
    );

    proto_register_field_array(PROTO_PCIE, HF_PCIE, array_length(HF_PCIE));

    PCIE_HANDLE = register_dissector("pcie", dissect_pcie, PROTO_PCIE);
}

static void proto_register_pcie_frame() {
    PROTO_PCIE_FRAME = proto_register_protocol(
        "PCI Express Frame",
        "PCIe Frame",
        "pcie.frame"
    );

    proto_register_field_array(PROTO_PCIE_FRAME, HF_PCIE_FRAME, array_length(HF_PCIE_FRAME));
}

static void proto_register_pcie_tlp() {
    PROTO_PCIE_TLP = proto_register_protocol(
        "PCI Express Transaction Layer Packet",
        "PCIe TLP",
        "pcie.tlp"
    );

    proto_register_field_array(PROTO_PCIE_TLP, HF_PCIE_TLP, array_length(HF_PCIE_TLP));
}

void proto_register_pcie() {
    proto_register_subtree_array(ETT, array_length(ETT));

    // PCIe Capture
    proto_register_pcie_capture();

    // PCIe Frame
    proto_register_pcie_frame();

    // PCIe TLP
    proto_register_pcie_tlp();
}

void proto_reg_handoff_pcie() {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER11, PCIE_HANDLE);
}
