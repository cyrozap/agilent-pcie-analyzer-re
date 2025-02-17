// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_pcie_capture.c - PCIe capture dissector for Wireshark.
 *  Copyright (C) 2023-2025  Forest Crossman <cyrozap@gmail.com>
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

#include <stdbool.h>
#include <stdint.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <wiretap/wtap.h>

#include "proto_pcie_capture.h"


static const int PCIE_CAPTURE_HEADER_SIZE = 20;

static const true_false_string tfs_direction = { "Upstream", "Downstream" };

static const value_string LINK_SPEED[] = {
    { 0x1, "2.5 GT/s" },
    { 0x3, "5.0 GT/s" },
    { 0, NULL },
};

static const value_string LINK_WIDTH[] = {
    { 0, "x1" },
    { 1, "x2" },
    { 2, "x4" },
    { 3, "x8" },
    { 4, "x16" },
    { 0, NULL },
};

static dissector_handle_t PCIE_HANDLE = NULL;
static dissector_handle_t PCIE_FRAME_HANDLE = NULL;

static int PROTO_PCIE = -1;

static int HF_PCIE_RECORD = -1;
static int HF_PCIE_TIMESTAMP_NS = -1;
static int HF_PCIE_LFSR = -1;
static int HF_PCIE_METADATA_INFO = -1;
static int HF_PCIE_METADATA_INFO_EXTRA_METADATA_PRESENT = -1;
static int HF_PCIE_METADATA_INFO_METADATA_OFFSET = -1;
static int HF_PCIE_FLAGS = -1;
static int HF_PCIE_GAP = -1;
static int HF_PCIE_SCRAMBLED = -1;
static int HF_PCIE_DIRECTION = -1;
static int HF_PCIE_ELECTRICAL_IDLE = -1;
static int HF_PCIE_DISPARITY_ERROR = -1;
static int HF_PCIE_CHANNEL_BONDED = -1;
static int HF_PCIE_LINK_SPEED = -1;
static int HF_PCIE_START_LANE = -1;
static int HF_PCIE_SYMBOL_ERROR = -1;
static int HF_PCIE_LINK_WIDTH = -1;
static int HF_PCIE_8B10B_META = -1;
static int HF_PCIE_8B10B_META_BLOCK = -1;
static int HF_PCIE_8B10B_META_BLOCK_K_SYMBOLS = -1;
static int HF_PCIE_8B10B_META_BLOCK_DISPARITY_POLARITY = -1;
static int HF_PCIE_EXTRA_META = -1;
static int HF_PCIE_LFSR_META = -1;
static int HF_PCIE_LFSR_META_BLOCK = -1;
static int HF_PCIE_LFSR_META_BLOCK_CONTROL = -1;
static int HF_PCIE_LFSR_META_BLOCK_CONTROL_LFSR_PRESENT = -1;
static int HF_PCIE_LFSR_META_BLOCK_CONTROL_TYPE = -1;
static int HF_PCIE_LFSR_META_BLOCK_CONTROL_LINK_SPEED = -1;
static int HF_PCIE_LFSR_META_BLOCK_IDLES_AFTER_32 = -1;
static int HF_PCIE_LFSR_META_BLOCK_IDLES_AFTER_64 = -1;
static int HF_PCIE_LFSR_META_BLOCK_ELECTRICAL_IDLE = -1;
static int HF_PCIE_LFSR_META_BLOCK_LFSR_STATE = -1;
static int HF_PCIE_LFSR_META_BLOCK_DATA_LEN = -1;
static int HF_PCIE_LFSR_META_BLOCK_DATA = -1;
static int HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META = -1;
static int HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK = -1;
static int HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK_K_SYMBOLS = -1;
static int HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK_DISPARITY_POLARITY = -1;

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
    { &HF_PCIE_LFSR,
        { "LFSR", "pcie.lfsr",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_METADATA_INFO,
        { "Metadata Info", "pcie.metadata_info",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_METADATA_INFO_EXTRA_METADATA_PRESENT,
        { "Extra Metadata Present", "pcie.metadata_info.extra_metadata_present",
        FT_BOOLEAN, 16,
        NULL, 0x8000,
        NULL, HFILL }
    },
    { &HF_PCIE_METADATA_INFO_METADATA_OFFSET,
        { "Metadata Offset", "pcie.metadata_info.metadata_offset",
        FT_UINT16, BASE_DEC,
        NULL, 0x7FFF,
        NULL, HFILL }
    },
    { &HF_PCIE_FLAGS,
        { "Flags", "pcie.flags",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_GAP,
        { "Gap", "pcie.gap",
        FT_BOOLEAN, 32,
        NULL, 0x40000000,
        NULL, HFILL }
    },
    { &HF_PCIE_SCRAMBLED,
        { "Scrambled", "pcie.scrambled",
        FT_BOOLEAN, 32,
        NULL, 0x20000000,
        NULL, HFILL }
    },
    { &HF_PCIE_DIRECTION,
        { "Direction", "pcie.direction",
        FT_BOOLEAN, 32,
        TFS(&tfs_direction), 0x10000000,
        NULL, HFILL }
    },
    { &HF_PCIE_ELECTRICAL_IDLE,
        { "Electrical Idle", "pcie.electrical_idle",
        FT_UINT32, BASE_HEX,
        NULL, 0x0FFFF000,
        NULL, HFILL }
    },
    { &HF_PCIE_DISPARITY_ERROR,
        { "Disparity Error", "pcie.disparity_error",
        FT_BOOLEAN, 32,
        NULL, 0x00000800,
        NULL, HFILL }
    },
    { &HF_PCIE_CHANNEL_BONDED,
        { "Channel Bonded", "pcie.channel_bonded",
        FT_BOOLEAN, 32,
        NULL, 0x00000400,
        NULL, HFILL }
    },
    { &HF_PCIE_LINK_SPEED,
        { "Link Speed", "pcie.link_speed",
        FT_UINT32, BASE_HEX,
        VALS(LINK_SPEED), 0x00000300,
        NULL, HFILL }
    },
    { &HF_PCIE_START_LANE,
        { "Start Lane", "pcie.start_lane",
        FT_UINT32, BASE_DEC,
        NULL, 0x000000F0,
        NULL, HFILL }
    },
    { &HF_PCIE_SYMBOL_ERROR,
        { "Symbol Error", "pcie.symbol_error",
        FT_BOOLEAN, 32,
        NULL, 0x00000008,
        NULL, HFILL }
    },
    { &HF_PCIE_LINK_WIDTH,
        { "Link Width", "pcie.link_width",
        FT_UINT32, BASE_DEC,
        VALS(LINK_WIDTH), 0x00000007,
        NULL, HFILL }
    },
    { &HF_PCIE_8B10B_META,
        { "8b/10b Metadata", "pcie.8b10b_meta",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_8B10B_META_BLOCK,
        { "Metadata Block", "pcie.8b10b_meta.block",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_8B10B_META_BLOCK_K_SYMBOLS,
        { "K Symbols", "pcie.8b10b_meta.block.k_symbols",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_8B10B_META_BLOCK_DISPARITY_POLARITY,
        { "Disparity Polarity", "pcie.8b10b_meta.block.disparity_polarity",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_EXTRA_META,
        { "Extra Metadata", "pcie.extra_meta",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META,
        { "LFSR Metadata", "pcie.lfsr_meta",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK,
        { "Metadata Block", "pcie.lfsr_meta.block",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_CONTROL,
        { "Control Byte", "pcie.lfsr_meta.block.control",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_CONTROL_LFSR_PRESENT,
        { "LFSR State Present", "pcie.lfsr_meta.block.control.lfsr_present",
        FT_BOOLEAN, 8,
        NULL, 0x40,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_CONTROL_TYPE,
        { "Type", "pcie.lfsr_meta.block.control.type",
        FT_UINT8, BASE_HEX,
        NULL, 0x30,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_CONTROL_LINK_SPEED,
        { "Link Speed", "pcie.lfsr_meta.block.control.link_speed",
        FT_UINT8, BASE_HEX,
        VALS(LINK_SPEED), 0x03,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_IDLES_AFTER_32,
        { "Idles After", "pcie.lfsr_meta.block.idles_after",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_IDLES_AFTER_64,
        { "Idles After", "pcie.lfsr_meta.block.idles_after",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_ELECTRICAL_IDLE,
        { "Electrical Idle", "pcie.lfsr_meta.block.electrical_idle",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_LFSR_STATE,
        { "LFSR State", "pcie.lfsr_meta.block.lfsr_state",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_DATA_LEN,
        { "Data Length", "pcie.lfsr_meta.block.data_len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_DATA,
        { "Data", "pcie.lfsr_meta.block.data",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META,
        { "8b/10b Metadata", "pcie.lfsr_meta.block.data_8b10b_meta",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK,
        { "Metadata Block", "pcie.lfsr_meta.block.data_8b10b_meta.block",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK_K_SYMBOLS,
        { "K Symbols", "pcie.lfsr_meta.block.data_8b10b_meta.block.k_symbols",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK_DISPARITY_POLARITY,
        { "Disparity Polarity", "pcie.lfsr_meta.block.data_8b10b_meta.block.disparity_polarity",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static int ETT_PCIE = -1;
static int ETT_PCIE_METADATA_INFO = -1;
static int ETT_PCIE_FLAGS = -1;
static int ETT_PCIE_8B10B_META = -1;
static int ETT_PCIE_8B10B_META_BLOCK = -1;
static int ETT_PCIE_LFSR_META = -1;
static int ETT_PCIE_LFSR_META_BLOCK = -1;
static int ETT_PCIE_LFSR_META_BLOCK_CONTROL = -1;
static int ETT_PCIE_LFSR_META_BLOCK_DATA_8B10B_META = -1;
static int ETT_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK = -1;
static int * const ETT[] = {
        &ETT_PCIE,
        &ETT_PCIE_METADATA_INFO,
        &ETT_PCIE_FLAGS,
        &ETT_PCIE_8B10B_META,
        &ETT_PCIE_8B10B_META_BLOCK,
        &ETT_PCIE_LFSR_META,
        &ETT_PCIE_LFSR_META_BLOCK,
        &ETT_PCIE_LFSR_META_BLOCK_CONTROL,
        &ETT_PCIE_LFSR_META_BLOCK_DATA_8B10B_META,
        &ETT_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK,
};

static expert_field EI_PCIE_DISPARITY_ERROR = EI_INIT;
static expert_field EI_PCIE_SYMBOL_ERROR = EI_INIT;

static ei_register_info EI_PCIE[] = {
    { &EI_PCIE_DISPARITY_ERROR,
        { "pcie.disparity_error.ei", PI_CHECKSUM, PI_WARN,
            "Disparity error", EXPFILL }
    },
    { &EI_PCIE_SYMBOL_ERROR,
        { "pcie.symbol_error.ei", PI_CHECKSUM, PI_WARN,
            "Symbol error", EXPFILL }
    },
};

static int dissect_pcie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_item * pcie_tree_item = proto_tree_add_item(tree, PROTO_PCIE, tvb, 0, PCIE_CAPTURE_HEADER_SIZE, ENC_NA);
    proto_tree * pcie_tree = proto_item_add_subtree(pcie_tree_item, ETT_PCIE);
    proto_tree_add_item(pcie_tree, HF_PCIE_RECORD, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pcie_tree, HF_PCIE_TIMESTAMP_NS, tvb, 4, 8, ENC_LITTLE_ENDIAN);

    bool extra_metadata_present = false;
    uint32_t metadata_offset = 0;
    if (tvb_get_letohl(tvb, 12) != 0) {
        proto_tree_add_item(pcie_tree, HF_PCIE_LFSR, tvb, 12, 2, ENC_LITTLE_ENDIAN);

        proto_item * metadata_info_tree_item = proto_tree_add_item(pcie_tree, HF_PCIE_METADATA_INFO, tvb, 14, 2, ENC_NA);
        proto_tree * metadata_info_tree = proto_item_add_subtree(metadata_info_tree_item, ETT_PCIE_METADATA_INFO);

        proto_tree_add_item_ret_boolean(metadata_info_tree, HF_PCIE_METADATA_INFO_EXTRA_METADATA_PRESENT, tvb, 14, 2, ENC_LITTLE_ENDIAN, &extra_metadata_present);
        proto_tree_add_item_ret_uint(metadata_info_tree, HF_PCIE_METADATA_INFO_METADATA_OFFSET, tvb, 14, 2, ENC_LITTLE_ENDIAN, &metadata_offset);
        proto_item_append_text(metadata_info_tree_item, ": Offset: %d", metadata_offset);
        if (extra_metadata_present) {
            proto_item_append_text(metadata_info_tree_item, ", extra metadata present");
        }
    }

    proto_item * flags_tree_item = proto_tree_add_item(pcie_tree, HF_PCIE_FLAGS, tvb, 16, 4, ENC_NA);
    proto_tree * flags_tree = proto_item_add_subtree(flags_tree_item, ETT_PCIE_FLAGS);

    proto_tree_add_item(flags_tree, HF_PCIE_GAP, tvb, 16, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(flags_tree, HF_PCIE_SCRAMBLED, tvb, 16, 4, ENC_LITTLE_ENDIAN);

    bool direction = 0;
    proto_tree_add_item_ret_boolean(flags_tree, HF_PCIE_DIRECTION, tvb, 16, 4, ENC_LITTLE_ENDIAN, &direction);

    proto_tree_add_item(flags_tree, HF_PCIE_ELECTRICAL_IDLE, tvb, 16, 4, ENC_LITTLE_ENDIAN);

    bool disparity_error = 0;
    proto_item * disparity_error_item = proto_tree_add_item_ret_boolean(flags_tree, HF_PCIE_DISPARITY_ERROR, tvb, 16, 4, ENC_LITTLE_ENDIAN, &disparity_error);

    proto_tree_add_item(flags_tree, HF_PCIE_CHANNEL_BONDED, tvb, 16, 4, ENC_LITTLE_ENDIAN);

    uint32_t link_speed = 0;
    proto_tree_add_item_ret_uint(flags_tree, HF_PCIE_LINK_SPEED, tvb, 16, 4, ENC_LITTLE_ENDIAN, &link_speed);

    proto_tree_add_item(flags_tree, HF_PCIE_START_LANE, tvb, 16, 4, ENC_LITTLE_ENDIAN);

    bool symbol_error = 0;
    proto_item * symbol_error_item = proto_tree_add_item_ret_boolean(flags_tree, HF_PCIE_SYMBOL_ERROR, tvb, 16, 4, ENC_LITTLE_ENDIAN, &symbol_error);

    uint32_t link_width = 0;
    proto_tree_add_item_ret_uint(flags_tree, HF_PCIE_LINK_WIDTH, tvb, 16, 4, ENC_LITTLE_ENDIAN, &link_width);

    proto_item_append_text(flags_tree_item, ": %s", direction ? "Upstream" : "Downstream");
    const char * link_speed_str = try_val_to_str(link_speed, LINK_SPEED);
    if (link_speed_str != NULL) {
        proto_item_append_text(flags_tree_item, ", %s", link_speed_str);
    }
    const char * link_width_str = try_val_to_str(link_width, LINK_WIDTH);
    if (link_width_str != NULL) {
        proto_item_append_text(flags_tree_item, ", %s", link_width_str);
    }
    if (disparity_error) {
        proto_item_append_text(flags_tree_item, ", Disparity Error");
        expert_add_info(pinfo, disparity_error_item, &EI_PCIE_DISPARITY_ERROR);
    }
    if (symbol_error) {
        proto_item_append_text(flags_tree_item, ", Symbol Error");
        expert_add_info(pinfo, symbol_error_item, &EI_PCIE_SYMBOL_ERROR);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCIe");

    if (direction) {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "Downstream Device");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "Upstream Device");
    } else {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "Upstream Device");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "Downstream Device");
    }

    tvbuff_t * frame_tvb;
    if (metadata_offset > 0) {
        frame_tvb = tvb_new_subset_length(tvb, PCIE_CAPTURE_HEADER_SIZE, metadata_offset);
    } else {
        frame_tvb = tvb_new_subset_remaining(tvb, PCIE_CAPTURE_HEADER_SIZE);
    }
    call_dissector(PCIE_FRAME_HANDLE, frame_tvb, pinfo, tree);

    if (metadata_offset > 0) {
        tvbuff_t * meta_tvb = tvb_new_subset_remaining(tvb, PCIE_CAPTURE_HEADER_SIZE + metadata_offset);

        int meta_len = 2 * ((metadata_offset + (8 - 1)) / 8);
        if (meta_len <= tvb_captured_length(meta_tvb)) {
            proto_item * meta_tree_item = proto_tree_add_item(pcie_tree, HF_PCIE_8B10B_META, meta_tvb, 0, meta_len, ENC_NA);
            proto_tree * meta_tree = proto_item_add_subtree(meta_tree_item, ETT_PCIE_8B10B_META);

            for (int offset = 0; offset < meta_len; offset += 2) {
                proto_item * meta_block_tree_item = proto_tree_add_item(meta_tree, HF_PCIE_8B10B_META_BLOCK, meta_tvb, offset, 2, ENC_NA);
                proto_tree * meta_block_tree = proto_item_add_subtree(meta_block_tree_item, ETT_PCIE_8B10B_META_BLOCK);

                proto_tree_add_item(meta_block_tree, HF_PCIE_8B10B_META_BLOCK_K_SYMBOLS, meta_tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(meta_block_tree, HF_PCIE_8B10B_META_BLOCK_DISPARITY_POLARITY, meta_tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            }

            bool skip_lfsr = false;
            int extra_meta_len = 0;
            int next_len = 0;
            tvbuff_t * extra_meta_tvb = tvb_new_subset_remaining(meta_tvb, meta_len);
            if (extra_metadata_present) {
                uint16_t start = tvb_get_ntohs(extra_meta_tvb, 0);
                extra_meta_len += 2;

                if (start & 0x0001) {
                    int len = 0;
                    while (extra_meta_len < tvb_captured_length(extra_meta_tvb)) {
                        uint16_t word = tvb_get_ntohs(extra_meta_tvb, extra_meta_len);
                        extra_meta_len += 2;

                        if ((word & 0x0003) == 0) {
                            skip_lfsr = true;
                            break;
                        }

                        len = word >> 4;
                        if ((word & 0x0003) == 1) {
                            next_len = len;
                            break;
                        }

                        extra_meta_len += len;
                    }
                } else {
                    skip_lfsr = true;
                }

                if (next_len == 0) {
                    skip_lfsr = true;
                }

                proto_tree_add_item(pcie_tree, HF_PCIE_EXTRA_META, extra_meta_tvb, 0, extra_meta_len, ENC_NA);
            }

            tvbuff_t * lfsr_meta_tvb = tvb_new_subset_remaining(extra_meta_tvb, extra_meta_len);
            if (tvb_captured_length(lfsr_meta_tvb) && !skip_lfsr) {

                proto_item * lfsr_meta_tree_item = proto_tree_add_item(pcie_tree, HF_PCIE_LFSR_META, lfsr_meta_tvb, 0, -1, ENC_NA);
                proto_tree * lfsr_meta_tree = proto_item_add_subtree(lfsr_meta_tree_item, ETT_PCIE_LFSR_META);

                for (int lfsr_meta_offset = 0; lfsr_meta_offset < tvb_captured_length(lfsr_meta_tvb); ) {
                    /* Each type is defined as follows:
                     *
                     * Type 1:
                     *  - Idles After (32-bit, BE)
                     *  - Optional: LFSR State (16-bit, BE)
                     *  - Data Size / 8b10b Metadata Offset (16-bit, BE)
                     *  - Data
                     *  - 8b10b Metadata
                     *
                     * Type 2:
                     *  - Idles After (64-bit, BE)
                     *  - Optional: LFSR State (16-bit, BE)
                     *  - Data Size / 8b10b Metadata Offset (16-bit, LE)
                     *  - Data
                     *  - 8b10b Metadata
                     *
                     * Type 3:
                     *  - Idles After (64-bit, BE)
                     *  - Electrical Idle State (16-bit, LE)
                     *  - Optional: LFSR State (16-bit, BE)
                     *  - Data Size / 8b10b Metadata Offset (16-bit, LE)
                     *  - Data
                     *  - 8b10b Metadata
                     */

                    uint8_t control = tvb_get_uint8(lfsr_meta_tvb, lfsr_meta_offset);
                    uint8_t type = (control & 0x30) >> 4;
                    bool lfsr_state_present = (control & 0x40) != 0;

                    if (!(1 <= type && type <= 3)) {
                        /* Invalid type */
                        /* TODO: Add Expert Info */
                        break;
                    }

                    /* Default config for Type 1 */
                    bool idles_after_is_64_bit = false;
                    bool electrical_idle_present = false;
                    uint32_t data_len_encoding = ENC_BIG_ENDIAN;

                    if (type >= 2) {
                        idles_after_is_64_bit = true;
                        data_len_encoding = ENC_LITTLE_ENDIAN;
                    }

                    if (type >= 3) {
                        electrical_idle_present = true;
                    }

                    /* Get block length based on configuration */
                    int lfsr_meta_block_len = 1;
                    if (!idles_after_is_64_bit) {
                        lfsr_meta_block_len += 4;
                    } else {
                        lfsr_meta_block_len += 8;
                    }
                    if (electrical_idle_present) {
                        lfsr_meta_block_len += 2;
                    }
                    if (lfsr_state_present) {
                        lfsr_meta_block_len += 2;
                    }
                    /* Peek at the data length */
                    uint16_t data_len = 0;
                    if (data_len_encoding == ENC_BIG_ENDIAN) {
                        data_len = tvb_get_ntohs(lfsr_meta_tvb, lfsr_meta_offset + lfsr_meta_block_len);
                    } else {
                        data_len = tvb_get_letohs(lfsr_meta_tvb, lfsr_meta_offset + lfsr_meta_block_len);
                    }
                    lfsr_meta_block_len += 2;
                    lfsr_meta_block_len += data_len;
                    int eight_b_ten_b_meta_len = 2 * ((data_len + (8 - 1)) / 8);
                    lfsr_meta_block_len += eight_b_ten_b_meta_len;

                    /* Begin dissecting the metadata block */
                    proto_item * lfsr_meta_block_tree_item = proto_tree_add_item(lfsr_meta_tree, HF_PCIE_LFSR_META_BLOCK, lfsr_meta_tvb, lfsr_meta_offset, lfsr_meta_block_len, ENC_NA);
                    proto_tree * lfsr_meta_block_tree = proto_item_add_subtree(lfsr_meta_block_tree_item, ETT_PCIE_LFSR_META_BLOCK);

                    proto_item * lfsr_meta_block_control_tree_item = proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_CONTROL, lfsr_meta_tvb, lfsr_meta_offset, 1, ENC_BIG_ENDIAN);
                    proto_tree * lfsr_meta_block_control_tree = proto_item_add_subtree(lfsr_meta_block_control_tree_item, ETT_PCIE_LFSR_META_BLOCK_CONTROL);
                    proto_tree_add_item(lfsr_meta_block_control_tree, HF_PCIE_LFSR_META_BLOCK_CONTROL_LFSR_PRESENT, lfsr_meta_tvb, lfsr_meta_offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(lfsr_meta_block_control_tree, HF_PCIE_LFSR_META_BLOCK_CONTROL_TYPE, lfsr_meta_tvb, lfsr_meta_offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(lfsr_meta_block_control_tree, HF_PCIE_LFSR_META_BLOCK_CONTROL_LINK_SPEED, lfsr_meta_tvb, lfsr_meta_offset, 1, ENC_BIG_ENDIAN);
                    lfsr_meta_offset += 1;

                    if (!idles_after_is_64_bit) {
                        proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_IDLES_AFTER_32, lfsr_meta_tvb, lfsr_meta_offset, 4, ENC_BIG_ENDIAN);
                        lfsr_meta_offset += 4;
                    } else {
                        proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_IDLES_AFTER_64, lfsr_meta_tvb, lfsr_meta_offset, 8, ENC_BIG_ENDIAN);
                        lfsr_meta_offset += 8;
                    }

                    if (electrical_idle_present) {
                        proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_ELECTRICAL_IDLE, lfsr_meta_tvb, lfsr_meta_offset, 2, ENC_LITTLE_ENDIAN);
                        lfsr_meta_offset += 2;
                    }

                    if (lfsr_state_present) {
                        proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_LFSR_STATE, lfsr_meta_tvb, lfsr_meta_offset, 2, ENC_BIG_ENDIAN);
                        lfsr_meta_offset += 2;
                    }

                    proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_DATA_LEN, lfsr_meta_tvb, lfsr_meta_offset, 2, data_len_encoding);
                    lfsr_meta_offset += 2;

                    proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_DATA, lfsr_meta_tvb, lfsr_meta_offset, data_len, ENC_NA);
                    lfsr_meta_offset += data_len;

                    /* Dissect 8b/10b metadata */
                    tvbuff_t * lfsr_meta_8b10b_tvb = tvb_new_subset_length(lfsr_meta_tvb, lfsr_meta_offset, eight_b_ten_b_meta_len);
                    proto_item * lfsr_meta_block_data_8b10b_meta_tree_item = proto_tree_add_item(lfsr_meta_block_tree, HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META, lfsr_meta_8b10b_tvb, 0, -1, ENC_NA);
                    proto_tree * lfsr_meta_block_data_8b10b_meta_tree = proto_item_add_subtree(lfsr_meta_block_data_8b10b_meta_tree_item, ETT_PCIE_LFSR_META_BLOCK_DATA_8B10B_META);

                    for (int offset = 0; offset < tvb_reported_length(lfsr_meta_8b10b_tvb); offset += 2) {
                        proto_item * meta_block_tree_item = proto_tree_add_item(lfsr_meta_block_data_8b10b_meta_tree, HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK, lfsr_meta_8b10b_tvb, offset, 2, ENC_NA);
                        proto_tree * meta_block_tree = proto_item_add_subtree(meta_block_tree_item, ETT_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK);

                        proto_tree_add_item(meta_block_tree, HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK_K_SYMBOLS, lfsr_meta_8b10b_tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(meta_block_tree, HF_PCIE_LFSR_META_BLOCK_DATA_8B10B_META_BLOCK_DISPARITY_POLARITY, lfsr_meta_8b10b_tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
                    }
                    lfsr_meta_offset += tvb_reported_length(lfsr_meta_8b10b_tvb);
                }
            }
        }
    }

    return tvb_captured_length(tvb);
}

void proto_register_pcie_capture() {
    proto_register_subtree_array(ETT, array_length(ETT));

    PROTO_PCIE = proto_register_protocol(
        "PCI Express Capture",
        "PCIe",
        "pcie"
    );

    proto_register_field_array(PROTO_PCIE, HF_PCIE, array_length(HF_PCIE));

    expert_module_t * expert = expert_register_protocol(PROTO_PCIE);
    expert_register_field_array(expert, EI_PCIE, array_length(EI_PCIE));

    PCIE_HANDLE = register_dissector("pcie", dissect_pcie, PROTO_PCIE);

    PCIE_FRAME_HANDLE = find_dissector_add_dependency("pcie.frame", PROTO_PCIE);
}

void proto_reg_handoff_pcie_capture() {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER11, PCIE_HANDLE);
}
