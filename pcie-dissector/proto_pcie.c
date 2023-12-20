// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_pcie.c - PCIe dissector for Wireshark.
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

#include <epan/conversation.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <wiretap/wtap.h>
#include <wsutil/crc32.h>

#include "proto_pcie.h"


typedef struct tlp_bdf_s {
    uint32_t bus;
    uint32_t dev;
    uint32_t fun;
} tlp_bdf_t;

typedef struct tlp_transaction_s {
    guint32 req_frame;
    guint32 cpl_frame;
    nstime_t req_time;
} tlp_transaction_t;

typedef struct tlp_conv_info_s {
    wmem_map_t *pdus_by_txid;
    wmem_map_t *pdus_by_record_num;
} tlp_conv_info_t;


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

static const value_string DLLP_TYPE[] = {
    { 0b00000000, "Ack" },
    { 0b00000001, "MRInit" },
    { 0b00000010, "Data_Link_Feature" },
    { 0b00010000, "Nak" },
    { 0b00100000, "PM_Enter_L1" },
    { 0b00100001, "PM_Enter_L23" },
    { 0b00100011, "PM_Active_State_Request_L1" },
    { 0b00100100, "PM_Request_Ack" },
    { 0b00110000, "Vendor-specific" },
    { 0b00110001, "NOP" },
    { 0b01000000, "InitFC1-P (VC0)" },
    { 0b01000001, "InitFC1-P (VC1)" },
    { 0b01000010, "InitFC1-P (VC2)" },
    { 0b01000011, "InitFC1-P (VC3)" },
    { 0b01000100, "InitFC1-P (VC4)" },
    { 0b01000101, "InitFC1-P (VC5)" },
    { 0b01000110, "InitFC1-P (VC6)" },
    { 0b01000111, "InitFC1-P (VC7)" },
    { 0b01010000, "InitFC1-NP (VC0)" },
    { 0b01010001, "InitFC1-NP (VC1)" },
    { 0b01010010, "InitFC1-NP (VC2)" },
    { 0b01010011, "InitFC1-NP (VC3)" },
    { 0b01010100, "InitFC1-NP (VC4)" },
    { 0b01010101, "InitFC1-NP (VC5)" },
    { 0b01010110, "InitFC1-NP (VC6)" },
    { 0b01010111, "InitFC1-NP (VC7)" },
    { 0b01100000, "InitFC1-Cpl (VC0)" },
    { 0b01100001, "InitFC1-Cpl (VC1)" },
    { 0b01100010, "InitFC1-Cpl (VC2)" },
    { 0b01100011, "InitFC1-Cpl (VC3)" },
    { 0b01100100, "InitFC1-Cpl (VC4)" },
    { 0b01100101, "InitFC1-Cpl (VC5)" },
    { 0b01100110, "InitFC1-Cpl (VC6)" },
    { 0b01100111, "InitFC1-Cpl (VC7)" },
    { 0b01110000, "MRInitFC1 (VL0)" },
    { 0b01110001, "MRInitFC1 (VL1)" },
    { 0b01110010, "MRInitFC1 (VL2)" },
    { 0b01110011, "MRInitFC1 (VL3)" },
    { 0b01110100, "MRInitFC1 (VL4)" },
    { 0b01110101, "MRInitFC1 (VL5)" },
    { 0b01110110, "MRInitFC1 (VL6)" },
    { 0b01110111, "MRInitFC1 (VL7)" },
    { 0b11000000, "InitFC2-P (VC0)" },
    { 0b11000001, "InitFC2-P (VC1)" },
    { 0b11000010, "InitFC2-P (VC2)" },
    { 0b11000011, "InitFC2-P (VC3)" },
    { 0b11000100, "InitFC2-P (VC4)" },
    { 0b11000101, "InitFC2-P (VC5)" },
    { 0b11000110, "InitFC2-P (VC6)" },
    { 0b11000111, "InitFC2-P (VC7)" },
    { 0b11010000, "InitFC2-NP (VC0)" },
    { 0b11010001, "InitFC2-NP (VC1)" },
    { 0b11010010, "InitFC2-NP (VC2)" },
    { 0b11010011, "InitFC2-NP (VC3)" },
    { 0b11010100, "InitFC2-NP (VC4)" },
    { 0b11010101, "InitFC2-NP (VC5)" },
    { 0b11010110, "InitFC2-NP (VC6)" },
    { 0b11010111, "InitFC2-NP (VC7)" },
    { 0b11100000, "InitFC2-Cpl (VC0)" },
    { 0b11100001, "InitFC2-Cpl (VC1)" },
    { 0b11100010, "InitFC2-Cpl (VC2)" },
    { 0b11100011, "InitFC2-Cpl (VC3)" },
    { 0b11100100, "InitFC2-Cpl (VC4)" },
    { 0b11100101, "InitFC2-Cpl (VC5)" },
    { 0b11100110, "InitFC2-Cpl (VC6)" },
    { 0b11100111, "InitFC2-Cpl (VC7)" },
    { 0b11110000, "MRInitFC2 (VL0)" },
    { 0b11110001, "MRInitFC2 (VL1)" },
    { 0b11110010, "MRInitFC2 (VL2)" },
    { 0b11110011, "MRInitFC2 (VL3)" },
    { 0b11110100, "MRInitFC2 (VL4)" },
    { 0b11110101, "MRInitFC2 (VL5)" },
    { 0b11110110, "MRInitFC2 (VL6)" },
    { 0b11110111, "MRInitFC2 (VL7)" },
    { 0b10000000, "UpdateFC-P (VC0)" },
    { 0b10000001, "UpdateFC-P (VC1)" },
    { 0b10000010, "UpdateFC-P (VC2)" },
    { 0b10000011, "UpdateFC-P (VC3)" },
    { 0b10000100, "UpdateFC-P (VC4)" },
    { 0b10000101, "UpdateFC-P (VC5)" },
    { 0b10000110, "UpdateFC-P (VC6)" },
    { 0b10000111, "UpdateFC-P (VC7)" },
    { 0b10010000, "UpdateFC-NP (VC0)" },
    { 0b10010001, "UpdateFC-NP (VC1)" },
    { 0b10010010, "UpdateFC-NP (VC2)" },
    { 0b10010011, "UpdateFC-NP (VC3)" },
    { 0b10010100, "UpdateFC-NP (VC4)" },
    { 0b10010101, "UpdateFC-NP (VC5)" },
    { 0b10010110, "UpdateFC-NP (VC6)" },
    { 0b10010111, "UpdateFC-NP (VC7)" },
    { 0b10100000, "UpdateFC-Cpl (VC0)" },
    { 0b10100001, "UpdateFC-Cpl (VC1)" },
    { 0b10100010, "UpdateFC-Cpl (VC2)" },
    { 0b10100011, "UpdateFC-Cpl (VC3)" },
    { 0b10100100, "UpdateFC-Cpl (VC4)" },
    { 0b10100101, "UpdateFC-Cpl (VC5)" },
    { 0b10100110, "UpdateFC-Cpl (VC6)" },
    { 0b10100111, "UpdateFC-Cpl (VC7)" },
    { 0b10110000, "MRUpdateFC (VL0)" },
    { 0b10110001, "MRUpdateFC (VL1)" },
    { 0b10110010, "MRUpdateFC (VL2)" },
    { 0b10110011, "MRUpdateFC (VL3)" },
    { 0b10110100, "MRUpdateFC (VL4)" },
    { 0b10110101, "MRUpdateFC (VL5)" },
    { 0b10110110, "MRUpdateFC (VL6)" },
    { 0b10110111, "MRUpdateFC (VL7)" },
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

static const value_string TLP_FMT_TYPE_SHORT[] = {
    { 0b00000000, "MRd" },
    { 0b00100000, "MRd" },
    { 0b00000001, "MRdLk" },
    { 0b00100001, "MRdLk" },
    { 0b01000000, "MWr" },
    { 0b01100000, "MWr" },
    { 0b00000010, "IORd" },
    { 0b01000010, "IOWr" },
    { 0b00000100, "CfgRd0" },
    { 0b01000100, "CfgWr0" },
    { 0b00000101, "CfgRd1" },
    { 0b01000101, "CfgWr1" },
    { 0b00110000, "Msg (Routed to Root Complex)" },
    { 0b00110001, "Msg (Routed by Address)" },
    { 0b00110010, "Msg (Routed by ID)" },
    { 0b00110011, "Msg (Broadcast from Root Complex)" },
    { 0b00110100, "Msg (Local - Terminate at Receiver)" },
    { 0b00110101, "Msg (Gathered and routed to Root Complex)" },
    { 0b00110110, "Msg (Reserved - Terminate at Receiver)" },
    { 0b00110111, "Msg (Reserved - Terminate at Receiver)" },
    { 0b01110000, "MsgD (Routed to Root Complex)" },
    { 0b01110001, "MsgD (Routed by Address)" },
    { 0b01110010, "MsgD (Routed by ID)" },
    { 0b01110011, "MsgD (Broadcast from Root Complex)" },
    { 0b01110100, "MsgD (Local - Terminate at Receiver)" },
    { 0b01110101, "MsgD (Gathered and routed to Root Complex)" },
    { 0b01110110, "MsgD (Reserved - Terminate at Receiver)" },
    { 0b01110111, "MsgD (Reserved - Terminate at Receiver)" },
    { 0b00001010, "Cpl" },
    { 0b01001010, "CplD" },
    { 0b00001011, "CplLk" },
    { 0b01001011, "CplDLk" },
    { 0b01001100, "FetchAdd" },
    { 0b01101100, "FetchAdd" },
    { 0b01001101, "Swap-32" },
    { 0b01101101, "Swap-64" },
    { 0b01001110, "CAS-32" },
    { 0b01101110, "CAS-64" },
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

static const value_string TLP_ADDRESS_TYPE[] = {
    { 0b00, "Untranslated" },
    { 0b01, "Translation Request" },
    { 0b10, "Translated" },
    { 0b11, "Reserved" },
    { 0, NULL },
};

static const value_string TLP_PROCESSING_HINT[] = {
    { 0b00, "Bi-directional data structure" },
    { 0b01, "Requester" },
    { 0b10, "Target" },
    { 0b11, "Target with Priority" },
    { 0, NULL },
};

static const value_string TLP_CPL_STATUS[] = {
    { 0b000, "Successful Completion (SC)" },
    { 0b001, "Unsupported Request (UR)" },
    { 0b010, "Configuration Request Retry Status (CRS)" },
    { 0b100, "Completer Abort (CA)" },
    { 0, NULL },
};

static const value_string TLP_CPL_STATUS_SHORT[] = {
    { 0b000, "SC" },
    { 0b001, "UR" },
    { 0b010, "CRS" },
    { 0b100, "CA" },
    { 0, NULL },
};

static const value_string CFG_REGS[] = {
    { 0x000, "DID/VID" },
    { 0x001, "Status/Command" },
    { 0x002, "Class/Revision" },
    { 0x003, "BIST/Header Type/Latency Timer/Cache Line Size" },
    { 0x00D, "Capabilities" },
    { 0x00F, "Interrupt Line/Pin" },
    { 0, NULL },
};

static const value_string TLP_MSG_CODES[] = {
    { 0b00000000, "Unlock" },
    { 0b00010000, "LTR" },
    { 0b00010010, "OBFF" },
    { 0b00010100, "PM_Active_State_Nak" },
    { 0b00011000, "PM_PME" },
    { 0b00011001, "PME_Turn_Off" },
    { 0b00011011, "PME_TO_Ack" },
    { 0b00100000, "Assert_INTA" },
    { 0b00100001, "Assert_INTB" },
    { 0b00100010, "Assert_INTC" },
    { 0b00100011, "Assert_INTD" },
    { 0b00100100, "Deassert_INTA" },
    { 0b00100101, "Deassert_INTB" },
    { 0b00100110, "Deassert_INTC" },
    { 0b00100111, "Deassert_INTD" },
    { 0b00110000, "ERR_COR" },
    { 0b00110001, "ERR_NONFATAL" },
    { 0b00110011, "ERR_FATAL" },
    { 0b01000000, "Attention_Indicator_Off" },
    { 0b01000001, "Attention_Indicator_On" },
    { 0b01000011, "Attention_Indicator_Blink" },
    { 0b01000100, "Power_Indicator_Off" },
    { 0b01000101, "Power_Indicator_On" },
    { 0b01000111, "Power_Indicator_Blink" },
    { 0b01001000, "Attention_Button_Pressed" },
    { 0b01010000, "Set_Slot_Power_Limit" },
    { 0b01010010, "PTM Request" },
    { 0b01010011, "PTM Response" },
    { 0b01111110, "Vendor_Defined Type 0" },
    { 0b01111111, "Vendor_Defined Type 1" },
    { 0, NULL },
};

static dissector_handle_t PCIE_HANDLE = NULL;
static dissector_handle_t PCIE_FRAME_HANDLE = NULL;
static dissector_handle_t PCIE_DLLP_HANDLE = NULL;
static dissector_handle_t PCIE_TLP_HANDLE = NULL;

static int PROTO_PCIE = -1;
static int PROTO_PCIE_FRAME = -1;
static int PROTO_PCIE_DLLP = -1;
static int PROTO_PCIE_TLP = -1;

static int HF_PCIE_RECORD = -1;
static int HF_PCIE_TIMESTAMP_NS = -1;
static int HF_PCIE_UNK = -1;
static int HF_PCIE_DATA_COUNT = -1;
static int HF_PCIE_DATA_VALID = -1;
static int HF_PCIE_DATA_VALID_COUNT = -1;
static int HF_PCIE_FLAGS = -1;
static int HF_PCIE_DIRECTION = -1;
static int HF_PCIE_DISPARITY_ERROR = -1;
static int HF_PCIE_SYMBOL_ERROR = -1;

static int HF_PCIE_FRAME_START_TAG = -1;
static int HF_PCIE_FRAME_TLP_RESERVED_AND_SEQ = -1;
static int HF_PCIE_FRAME_TLP_RESERVED = -1;
static int HF_PCIE_FRAME_TLP_SEQ = -1;
static int HF_PCIE_FRAME_TLP_LCRC = -1;
static int HF_PCIE_FRAME_END_TAG = -1;

static int HF_PCIE_DLLP_TYPE = -1;
static int HF_PCIE_DLLP_CRC = -1;

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
static int HF_PCIE_TLP_TAG_7_0 = -1;
static int HF_PCIE_TLP_TAG = -1;
static int HF_PCIE_TLP_LAST_FIRST_DW_BE = -1;
static int HF_PCIE_TLP_LAST_DW_BE = -1;
static int HF_PCIE_TLP_FIRST_DW_BE = -1;
static int HF_PCIE_TLP_MSG_CODE = -1;
static int HF_PCIE_TLP_ADDR_PH_32 = -1;
static int HF_PCIE_TLP_ADDR_PH_64 = -1;
static int HF_PCIE_TLP_ADDR_32 = -1;
static int HF_PCIE_TLP_ADDR_64 = -1;
static int HF_PCIE_TLP_PH = -1;
static int HF_PCIE_TLP_CPL_ID = -1;
static int HF_PCIE_TLP_CPL_BUS = -1;
static int HF_PCIE_TLP_CPL_DEV = -1;
static int HF_PCIE_TLP_CPL_FUN = -1;
static int HF_PCIE_TLP_REG = -1;
static int HF_PCIE_TLP_CPL_STATUS_BCM_BYTE_COUNT = -1;
static int HF_PCIE_TLP_CPL_STATUS = -1;
static int HF_PCIE_TLP_CPL_BCM = -1;
static int HF_PCIE_TLP_CPL_BYTE_COUNT = -1;
static int HF_PCIE_TLP_CPL_LOWER_ADDR = -1;
static int HF_PCIE_TLP_PAYLOAD = -1;
static int HF_PCIE_TLP_PAYLOAD_DW = -1;
static int HF_PCIE_TLP_ECRC = -1;
static int HF_PCIE_TLP_COMPLETION_IN = -1;
static int HF_PCIE_TLP_REQUEST_IN = -1;
static int HF_PCIE_TLP_COMPLETION_TIME = -1;

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
    { &HF_PCIE_DATA_COUNT,
        { "Data Count", "pcie.data_count",
        FT_NONE, BASE_NONE,
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
    { &HF_PCIE_FLAGS,
        { "Flags", "pcie.flags",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_DIRECTION,
        { "Direction", "pcie.direction",
        FT_BOOLEAN, 32,
        TFS(&tfs_direction), 0x10000000,
        NULL, HFILL }
    },
    { &HF_PCIE_DISPARITY_ERROR,
        { "Disparity Error", "pcie.disparity_error",
        FT_BOOLEAN, 32,
        NULL, 0x00000800,
        NULL, HFILL }
    },
    { &HF_PCIE_SYMBOL_ERROR,
        { "Symbol Error", "pcie.symbol_error",
        FT_BOOLEAN, 32,
        NULL, 0x00000008,
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
    { &HF_PCIE_FRAME_TLP_RESERVED_AND_SEQ,
        { "TLP Sequence Number", "pcie.frame.tlp.reserved_and_seq",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
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

static hf_register_info HF_PCIE_DLLP[] = {
    { &HF_PCIE_DLLP_TYPE,
        { "Type", "pcie.dllp.type",
        FT_UINT8, BASE_HEX,
        VALS(DLLP_TYPE), 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_DLLP_CRC,
        { "CRC", "pcie.dllp.crc",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static hf_register_info HF_PCIE_TLP[] = {
    { &HF_PCIE_TLP_DW0,
        { "TLP DW 0", "pcie.tlp.dw0",
        FT_NONE, BASE_NONE,
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
        VALS(TLP_ADDRESS_TYPE), 0b11 << 10,
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
    { &HF_PCIE_TLP_TAG_7_0,
        { "Tag[7:0]", "pcie.tlp.tag70",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_TAG,
        { "Tag[9:0]", "pcie.tlp.tag",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_LAST_FIRST_DW_BE,
        { "Last/First DW Byte Enable", "pcie.tlp.last_first_dw_be",
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
    { &HF_PCIE_TLP_MSG_CODE,
        { "Message Code", "pcie.tlp.msg.code",
        FT_UINT8, BASE_HEX,
        VALS(TLP_MSG_CODES), 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ADDR_PH_32,
        { "Address and Processing Hint", "pcie.tlp.addr_ph",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ADDR_PH_64,
        { "Address and Processing Hint", "pcie.tlp.addr_ph",
        FT_UINT64, BASE_HEX,
        NULL, 0x0,
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
    { &HF_PCIE_TLP_PH,
        { "Processing Hint", "pcie.tlp.ph",
        FT_UINT8, BASE_DEC,
        VALS(TLP_PROCESSING_HINT), 0x3,
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
        VALS(CFG_REGS), 0x0FFC,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_CPL_STATUS_BCM_BYTE_COUNT,
        { "Completion Status, BCM, and Byte Count", "pcie.tlp.cpl.status_bcm_byte_count",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
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
    { &HF_PCIE_TLP_PAYLOAD,
        { "Payload", "pcie.tlp.payload",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_PAYLOAD_DW,
        { "Payload DW", "pcie.tlp.payload.dw",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_ECRC,
        { "End-to-end CRC", "pcie.tlp.ecrc",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_COMPLETION_IN,
        { "Completion In", "pcie.tlp.completion_in",
        FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_REQUEST_IN,
        { "Request In", "pcie.tlp.completion_to",
        FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
        NULL, HFILL }
    },
    { &HF_PCIE_TLP_COMPLETION_TIME,
        { "Completion Time", "pcie.tlp.completion_time",
        FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static int ETT_PCIE = -1;
static int ETT_PCIE_DATA_COUNT = -1;
static int ETT_PCIE_FLAGS = -1;
static int ETT_PCIE_FRAME = -1;
static int ETT_PCIE_FRAME_TLP_RESERVED_AND_SEQ = -1;
static int ETT_PCIE_DLLP = -1;
static int ETT_PCIE_TLP = -1;
static int ETT_PCIE_TLP_DW0 = -1;
static int ETT_PCIE_TLP_FMT_TYPE = -1;
static int ETT_PCIE_TLP_REQ_ID = -1;
static int ETT_PCIE_TLP_CPL_ID = -1;
static int ETT_PCIE_TLP_CPL_STATUS_BCM_BYTE_COUNT = -1;
static int ETT_PCIE_TLP_LAST_FIRST_DW_BE = -1;
static int ETT_PCIE_TLP_ADDR_PH = -1;
static int ETT_PCIE_TLP_PAYLOAD = -1;
static int * const ETT[] = {
        &ETT_PCIE,
        &ETT_PCIE_DATA_COUNT,
        &ETT_PCIE_FLAGS,
        &ETT_PCIE_FRAME,
        &ETT_PCIE_FRAME_TLP_RESERVED_AND_SEQ,
        &ETT_PCIE_DLLP,
        &ETT_PCIE_TLP,
        &ETT_PCIE_TLP_DW0,
        &ETT_PCIE_TLP_FMT_TYPE,
        &ETT_PCIE_TLP_REQ_ID,
        &ETT_PCIE_TLP_CPL_ID,
        &ETT_PCIE_TLP_CPL_STATUS_BCM_BYTE_COUNT,
        &ETT_PCIE_TLP_LAST_FIRST_DW_BE,
        &ETT_PCIE_TLP_ADDR_PH,
        &ETT_PCIE_TLP_PAYLOAD,
};

static expert_field EI_PCIE_DISPARITY_ERROR = EI_INIT;
static expert_field EI_PCIE_SYMBOL_ERROR = EI_INIT;

static expert_field EI_PCIE_FRAME_TLP_RESERVED_SET = EI_INIT;
static expert_field EI_PCIE_FRAME_LCRC_INVALID = EI_INIT;
static expert_field EI_PCIE_FRAME_END_TAG_INVALID = EI_INIT;

static expert_field EI_PCIE_DLLP_CRC_INVALID = EI_INIT;

static expert_field EI_PCIE_TLP_CPL_STATUS_NOT_SUCCESSFUL = EI_INIT;
static expert_field EI_PCIE_TLP_ECRC_INVALID = EI_INIT;

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

static ei_register_info EI_PCIE_FRAME[] = {
    { &EI_PCIE_FRAME_TLP_RESERVED_SET,
        { "pcie.frame.tlp.reserved_bit_set", PI_PROTOCOL, PI_WARN,
            "Reserved bit set", EXPFILL }
    },
    { &EI_PCIE_FRAME_LCRC_INVALID,
        { "pcie.frame.tlp.lcrc_invalid", PI_CHECKSUM, PI_WARN,
            "LCRC is invalid", EXPFILL }
    },
    { &EI_PCIE_FRAME_END_TAG_INVALID,
        { "pcie.frame.end_tag_invalid", PI_PROTOCOL, PI_WARN,
            "End Tag is invalid", EXPFILL }
    },
};

static ei_register_info EI_PCIE_DLLP[] = {
    { &EI_PCIE_DLLP_CRC_INVALID,
        { "pcie.dllp.crc_invalid", PI_CHECKSUM, PI_WARN,
            "CRC is invalid", EXPFILL }
    },
};

static ei_register_info EI_PCIE_TLP[] = {
    { &EI_PCIE_TLP_CPL_STATUS_NOT_SUCCESSFUL,
        { "pcie.tlp.cpl.status_not_successful", PI_RESPONSE_CODE, PI_WARN,
            "Completion Status is not Successful Completion (SC)", EXPFILL }
    },
    { &EI_PCIE_TLP_ECRC_INVALID,
        { "pcie.tlp.ecrc_invalid", PI_CHECKSUM, PI_WARN,
            "ECRC is invalid", EXPFILL }
    },
};

static void dissect_tlp_mem_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70, bool addr64);
static void dissect_tlp_io_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70);
static void dissect_tlp_cfg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70);
static void dissect_tlp_msg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70);
static void dissect_tlp_cpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70);

static uint32_t extract_length_from_tlp_dw0(uint32_t tlp_dw0) {
    uint32_t length = tlp_dw0 & ((1 << 10) - 1);

    if (length == 0) {
        length = 1 << 10;
    }

    return length;
}

static bool is_posted_request(uint32_t fmt_type) {
    /* Memory Write */
    if ((fmt_type & 0b11011111) == 0b01000000)
        return true;

    /* Message */
    if ((fmt_type & 0b10111000) == 0b00110000)
        return true;

    return false;
}

static bool is_completion(uint32_t fmt_type) {
    return (fmt_type & 0b10111110) == 0b00001010;
}

// Borrowed from epan/dissectors/packet-btbredr_rf.c
static uint8_t reverse_bits(uint8_t value) {
    value = ((value >> 1) & 0x55) | ((value << 1) & 0xaa);
    value = ((value >> 2) & 0x33) | ((value << 2) & 0xcc);
    value = ((value >> 4) & 0x0f) | ((value << 4) & 0xf0);
    return value;
}

static uint16_t dllp_crc(const uint8_t *buf, uint32_t len) {
    uint16_t crc = 0xFFFF;
    for (uint32_t i = 0; i < len; i++) {
        for (uint32_t j = 0; j < 8; j++) {
            uint16_t bit = (buf[i] >> j) & 1;
            bit ^= crc >> 15;
            crc = (crc << 1) | bit;
            if (bit) {
                crc ^= 0x100b & 0xfffe;
            }
        }
    }
    crc ^= 0xFFFF;
    crc = (reverse_bits(crc) << 8) | reverse_bits(crc >> 8);
    return crc;
}

static uint16_t dllp_crc16_tvb_offset(tvbuff_t *tvb, uint32_t offset, uint32_t len) {
    tvb_ensure_bytes_exist(tvb, offset, len);
    const uint8_t * buf = tvb_get_ptr(tvb, offset, len);

    return dllp_crc(buf, len);
}

static int dissect_pcie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_item * pcie_tree_item = proto_tree_add_item(tree, PROTO_PCIE, tvb, 0, PCIE_CAPTURE_HEADER_SIZE, ENC_NA);
    proto_tree * pcie_tree = proto_item_add_subtree(pcie_tree_item, ETT_PCIE);
    proto_tree_add_item(pcie_tree, HF_PCIE_RECORD, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pcie_tree, HF_PCIE_TIMESTAMP_NS, tvb, 4, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pcie_tree, HF_PCIE_UNK, tvb, 12, 2, ENC_LITTLE_ENDIAN);

    proto_item * data_count_tree_item = proto_tree_add_item(pcie_tree, HF_PCIE_DATA_COUNT, tvb, 14, 2, ENC_NA);
    proto_tree * data_count_tree = proto_item_add_subtree(data_count_tree_item, ETT_PCIE_DATA_COUNT);

    gboolean data_valid = false;
    proto_tree_add_item_ret_boolean(data_count_tree, HF_PCIE_DATA_VALID, tvb, 14, 2, ENC_LITTLE_ENDIAN, &data_valid);

    uint32_t data_valid_count = 0;
    proto_tree_add_item_ret_uint(data_count_tree, HF_PCIE_DATA_VALID_COUNT, tvb, 14, 2, ENC_LITTLE_ENDIAN, &data_valid_count);

    proto_item_append_text(data_count_tree_item, ": %d", data_valid_count);
    if (data_valid) {
        proto_item_append_text(data_count_tree_item, " (Valid)");
    }

    proto_item * flags_tree_item = proto_tree_add_item(pcie_tree, HF_PCIE_FLAGS, tvb, 16, 4, ENC_NA);
    proto_tree * flags_tree = proto_item_add_subtree(flags_tree_item, ETT_PCIE_FLAGS);

    gboolean direction = 0;
    proto_tree_add_item_ret_boolean(flags_tree, HF_PCIE_DIRECTION, tvb, 16, 4, ENC_LITTLE_ENDIAN, &direction);
    gboolean disparity_error = 0;
    proto_item * disparity_error_item = proto_tree_add_item_ret_boolean(flags_tree, HF_PCIE_DISPARITY_ERROR, tvb, 16, 4, ENC_LITTLE_ENDIAN, &disparity_error);
    gboolean symbol_error = 0;
    proto_item * symbol_error_item = proto_tree_add_item_ret_boolean(flags_tree, HF_PCIE_SYMBOL_ERROR, tvb, 16, 4, ENC_LITTLE_ENDIAN, &symbol_error);

    proto_item_append_text(flags_tree_item, ": %s", direction ? "Upstream" : "Downstream");
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
    if (data_valid) {
        frame_tvb = tvb_new_subset_length(tvb, PCIE_CAPTURE_HEADER_SIZE, data_valid_count);
    } else {
        frame_tvb = tvb_new_subset_remaining(tvb, PCIE_CAPTURE_HEADER_SIZE);
    }
    call_dissector(PCIE_FRAME_HANDLE, frame_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static int dissect_pcie_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    uint32_t frame_len = tvb_reported_length(tvb);

    proto_item * frame_tree_item = proto_tree_add_item(tree, PROTO_PCIE_FRAME, tvb, 0, frame_len, ENC_NA);
    proto_tree * frame_tree = proto_item_add_subtree(frame_tree_item, ETT_PCIE_FRAME);

    uint32_t start_tag = 0;
    proto_tree_add_item_ret_uint(frame_tree, HF_PCIE_FRAME_START_TAG, tvb, 0, 1, ENC_BIG_ENDIAN, &start_tag);

    switch (start_tag) {
        case K_27_7:
            {
                proto_item * tlp_seq_tree_item = proto_tree_add_item(frame_tree, HF_PCIE_FRAME_TLP_RESERVED_AND_SEQ, tvb, 1, 2, ENC_NA);
                proto_tree * tlp_seq_tree = proto_item_add_subtree(tlp_seq_tree_item, ETT_PCIE_FRAME_TLP_RESERVED_AND_SEQ);

                uint32_t tlp_res = 0;
                proto_item * tlp_res_item = proto_tree_add_item_ret_uint(tlp_seq_tree, HF_PCIE_FRAME_TLP_RESERVED, tvb, 1, 2, ENC_BIG_ENDIAN, &tlp_res);
                if (tlp_res != 0) {
                    expert_add_info(pinfo, tlp_res_item, &EI_PCIE_FRAME_TLP_RESERVED_SET);
                }

                uint32_t tlp_seq = 0;
                proto_tree_add_item_ret_uint(tlp_seq_tree, HF_PCIE_FRAME_TLP_SEQ, tvb, 1, 2, ENC_BIG_ENDIAN, &tlp_seq);

                proto_item_append_text(tlp_seq_tree_item, ": %d", tlp_seq);

                const uint32_t tlp_offset = 3;

                // Peek at the first DW of the TLP to determine the length of the TLP.
                uint32_t tlp_dw0 = tvb_get_ntohl(tvb, tlp_offset);
                uint32_t tlp_fmt_type = tlp_dw0 >> 24;
                uint32_t tlp_fmt = (tlp_fmt_type >> 5);
                uint32_t header_dw_count = 3;
                if (tlp_fmt & 0b001) {
                    header_dw_count = 4;
                }
                uint32_t payload_dw_count = 0;
                if (tlp_fmt & 0b010) {
                    payload_dw_count = extract_length_from_tlp_dw0(tlp_dw0);
                }
                uint32_t ecrc_dw_count = 0;
                if (tlp_dw0 & (1 << 15)) {
                    ecrc_dw_count = 1;
                }
                uint32_t tlp_len = 4 * (header_dw_count + payload_dw_count + ecrc_dw_count);

                // Dissect the TLP.
                tvbuff_t * tlp_tvb = tvb_new_subset_length(tvb, tlp_offset, tlp_len);
                call_dissector(PCIE_TLP_HANDLE, tlp_tvb, pinfo, tree);

                uint32_t lcrc = 0;
                proto_item * lcrc_item = proto_tree_add_item_ret_uint(frame_tree, HF_PCIE_FRAME_TLP_LCRC, tvb, tlp_offset+tlp_len, 4, ENC_LITTLE_ENDIAN, &lcrc);

                // Verify the LCRC in the frame matches the calculated value.
                if (lcrc != crc32_ccitt_tvb_offset(tvb, 1, 2 + tlp_len)) {
                    expert_add_info(pinfo, lcrc_item, &EI_PCIE_FRAME_LCRC_INVALID);
                }

                uint32_t end_tag = 0;
                proto_item * end_tag_item = proto_tree_add_item_ret_uint(frame_tree, HF_PCIE_FRAME_END_TAG, tvb, tlp_offset+tlp_len+4, 1, ENC_BIG_ENDIAN, &end_tag);
                if (end_tag != K_29_7) {
                    expert_add_info(pinfo, end_tag_item, &EI_PCIE_FRAME_END_TAG_INVALID);
                }
            }
            break;
        case K_28_2:
            {
                tvbuff_t * dllp_tvb = tvb_new_subset_length(tvb, 1, 6);
                call_dissector(PCIE_DLLP_HANDLE, dllp_tvb, pinfo, tree);

                uint32_t end_tag = 0;
                proto_item * end_tag_item = proto_tree_add_item_ret_uint(frame_tree, HF_PCIE_FRAME_END_TAG, tvb, 7, 1, ENC_BIG_ENDIAN, &end_tag);
                if (end_tag != K_29_7) {
                    expert_add_info(pinfo, end_tag_item, &EI_PCIE_FRAME_END_TAG_INVALID);
                }
            }
            break;
        default:
            break;
    }

    return tvb_captured_length(tvb);
}

static int dissect_pcie_dllp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCIe DLLP");

    uint32_t dllp_len = tvb_reported_length(tvb);
    proto_item * dllp_tree_item = proto_tree_add_item(tree, PROTO_PCIE_DLLP, tvb, 0, dllp_len, ENC_NA);
    proto_tree * dllp_tree = proto_item_add_subtree(dllp_tree_item, ETT_PCIE_DLLP);
    proto_tree_add_item(dllp_tree, HF_PCIE_DLLP_TYPE, tvb, 0, 1, ENC_BIG_ENDIAN);

    uint32_t crc = 0;
    proto_item * crc_item = proto_tree_add_item_ret_uint(dllp_tree, HF_PCIE_DLLP_CRC, tvb, 4, 2, ENC_LITTLE_ENDIAN, &crc);
    if (crc != dllp_crc16_tvb_offset(tvb, 0, 4)) {
        expert_add_info(pinfo, crc_item, &EI_PCIE_DLLP_CRC_INVALID);
    }

    return tvb_captured_length(tvb);
}

static int dissect_pcie_tlp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCIe TLP");

    uint32_t tlp_len = tvb_reported_length(tvb);
    proto_item * tlp_tree_item = proto_tree_add_item(tree, PROTO_PCIE_TLP, tvb, 0, tlp_len, ENC_NA);
    proto_tree * tlp_tree = proto_item_add_subtree(tlp_tree_item, ETT_PCIE_TLP);

    proto_item * dw0_tree_item = proto_tree_add_item(tlp_tree, HF_PCIE_TLP_DW0, tvb, 0, 4, ENC_NA);
    proto_tree * dw0_tree = proto_item_add_subtree(dw0_tree_item, ETT_PCIE_TLP_DW0);

    uint32_t tlp_fmt_type = 0;
    proto_item * fmt_type_item = proto_tree_add_item_ret_uint(dw0_tree, HF_PCIE_TLP_FMT_TYPE, tvb, 0, 1, ENC_BIG_ENDIAN, &tlp_fmt_type);
    proto_tree * fmt_type_tree = proto_item_add_subtree(fmt_type_item, ETT_PCIE_TLP_FMT_TYPE);

    const char * tlp_fmt_type_str = try_val_to_str(tlp_fmt_type, TLP_FMT_TYPE_SHORT);
    if (tlp_fmt_type_str == NULL) {
        tlp_fmt_type_str = "Unknown TLP FMT";
    }
    proto_item_append_text(dw0_tree_item, ": %s", tlp_fmt_type_str);

    uint32_t tlp_fmt = 0;
    proto_tree_add_item_ret_uint(fmt_type_tree, HF_PCIE_TLP_FMT, tvb, 0, 1, ENC_BIG_ENDIAN, &tlp_fmt);

    if (tlp_fmt >= 0b100) {
        // TODO: Add support for TLP Prefixes.
        return tvb_captured_length(tvb);
    }

    uint32_t tlp_type = 0;
    proto_tree_add_item_ret_uint(fmt_type_tree, HF_PCIE_TLP_TYPE, tvb, 0, 1, ENC_BIG_ENDIAN, &tlp_type);

    // Fields Present in All TLP Headers
    uint32_t tag9 = 0;
    proto_tree_add_item_ret_uint(dw0_tree, HF_PCIE_TLP_T9, tvb, 1, 3, ENC_BIG_ENDIAN, &tag9);

    uint32_t traffic_class = 0;
    proto_tree_add_item_ret_uint(dw0_tree, HF_PCIE_TLP_TC, tvb, 1, 3, ENC_BIG_ENDIAN, &traffic_class);
    if (traffic_class > 0) {
        proto_item_append_text(dw0_tree_item, ", TC%d", traffic_class);
    }

    uint32_t tag8 = 0;
    proto_tree_add_item_ret_uint(dw0_tree, HF_PCIE_TLP_T8, tvb, 1, 3, ENC_BIG_ENDIAN, &tag8);

    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_ATTR2, tvb, 1, 3, ENC_BIG_ENDIAN);

    gboolean lightweight_notification = 0;
    proto_tree_add_item_ret_boolean(dw0_tree, HF_PCIE_TLP_LN, tvb, 1, 3, ENC_BIG_ENDIAN, &lightweight_notification);
    if (lightweight_notification) {
        proto_item_append_text(dw0_tree_item, ", LN");
    }

    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_TH, tvb, 1, 3, ENC_BIG_ENDIAN);

    gboolean tlp_digest = 0;
    proto_tree_add_item_ret_boolean(dw0_tree, HF_PCIE_TLP_TD, tvb, 1, 3, ENC_BIG_ENDIAN, &tlp_digest);

    gboolean error_poisoned = 0;
    proto_tree_add_item_ret_boolean(dw0_tree, HF_PCIE_TLP_EP, tvb, 1, 3, ENC_BIG_ENDIAN, &error_poisoned);
    if (error_poisoned) {
        proto_item_append_text(dw0_tree_item, ", EP");
    }

    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_ATTR10, tvb, 1, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item(dw0_tree, HF_PCIE_TLP_AT, tvb, 1, 3, ENC_BIG_ENDIAN);

    uint32_t payload_len = 0;
    proto_tree_add_item_ret_uint(dw0_tree, HF_PCIE_TLP_LENGTH, tvb, 1, 3, ENC_BIG_ENDIAN, &payload_len);
    if (payload_len > 0) {
        proto_item_append_text(dw0_tree_item, ", %d dw", payload_len);
    }

    bool has_payload = (tlp_fmt & 0b010) != 0;

    uint32_t req_id = 0;
    uint32_t tag70 = 0;

    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, tlp_fmt_type_str);

    switch (tlp_fmt_type) {
        case 0b00000000:
        case 0b00100000:
        case 0b01000000:
        case 0b01100000:
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %d dw", payload_len);
            dissect_tlp_mem_req(tvb, pinfo, tlp_tree, data, &req_id, &tag70, (tlp_fmt & 0b001) != 0);
            break;
        case 0b00000010:
        case 0b01000010:
            dissect_tlp_io_req(tvb, pinfo, tlp_tree, data, &req_id, &tag70);
            break;
        case 0b00000100:
        case 0b01000100:
        case 0b00000101:
        case 0b01000101:
            dissect_tlp_cfg_req(tvb, pinfo, tlp_tree, data, &req_id, &tag70);
            break;
        case 0b00001010:
        case 0b01001010:
            dissect_tlp_cpl(tvb, pinfo, tlp_tree, data, &req_id, &tag70);
            if (has_payload) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", %d dw", payload_len);
            }
            break;
        default:
            if ((tlp_fmt_type & 0b10111000) == 0b00110000) {
                dissect_tlp_msg_req(tvb, pinfo, tlp_tree, data, &req_id, &tag70);
                break;
            }
            return tvb_captured_length(tvb);
    }

    uint32_t tlp_tag = (tag9 << 9) | (tag8 << 8) | tag70;

    uint64_t tlp_transaction_id = (tlp_tag << 16) | req_id;

    conversation_t * conversation = find_or_create_conversation(pinfo);
    tlp_conv_info_t * tlp_info = (tlp_conv_info_t *)conversation_get_proto_data(conversation, PROTO_PCIE_TLP);
    tlp_transaction_t * tlp_trans = NULL;
    if (!tlp_info) {
        tlp_info = wmem_new(wmem_file_scope(), tlp_conv_info_t);
        tlp_info->pdus_by_txid=wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        tlp_info->pdus_by_record_num=wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(conversation, PROTO_PCIE_TLP, tlp_info);
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        if ((!is_completion(tlp_fmt_type)) && (!is_posted_request(tlp_fmt_type))) {
            /* This is a request */
            tlp_trans = wmem_new(wmem_file_scope(), tlp_transaction_t);
            tlp_trans->req_frame = pinfo->num;
            tlp_trans->cpl_frame = 0;
            tlp_trans->req_time = pinfo->fd->abs_ts;

            wmem_map_insert(tlp_info->pdus_by_txid, GUINT_TO_POINTER(tlp_transaction_id), (void *)tlp_trans);
            wmem_map_insert(tlp_info->pdus_by_record_num, GUINT_TO_POINTER(pinfo->num), (void *)tlp_trans);
        } else if (is_completion(tlp_fmt_type)) {
            /* This is a completion */
            tlp_trans = (tlp_transaction_t *)wmem_map_remove(tlp_info->pdus_by_txid, GUINT_TO_POINTER(tlp_transaction_id));
            if (tlp_trans) {
                tlp_trans->cpl_frame = pinfo->num;
                wmem_map_insert(tlp_info->pdus_by_record_num, GUINT_TO_POINTER(pinfo->num), (void *)tlp_trans);
            }
        }
    } else {
        tlp_trans = (tlp_transaction_t *)wmem_map_lookup(tlp_info->pdus_by_record_num, GUINT_TO_POINTER(pinfo->num));
    }

    int header_dw_count = 3 + (tlp_fmt & 0b001);

    if (has_payload) {
        proto_item * payload_tree_item = proto_tree_add_item(tlp_tree, HF_PCIE_TLP_PAYLOAD, tvb, 4*header_dw_count, 4*payload_len, ENC_NA);
        proto_tree * payload_tree = proto_item_add_subtree(payload_tree_item, ETT_PCIE_TLP_PAYLOAD);

        for (size_t i = 0; i < payload_len; i++) {
            proto_tree_add_item(payload_tree, HF_PCIE_TLP_PAYLOAD_DW, tvb, 4*(header_dw_count + i), 4, ENC_LITTLE_ENDIAN);
        }

        if (payload_len == 1) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": 0x%08x", tvb_get_letohl(tvb, 4*header_dw_count));
        }
    }

    if (tlp_digest) {
        int ecrc_dw_offset = header_dw_count;
        if (has_payload) {
            ecrc_dw_offset += payload_len;
        }

        uint32_t ecrc = 0;
        proto_item * ecrc_item = proto_tree_add_item_ret_uint(tlp_tree, HF_PCIE_TLP_ECRC, tvb, 4*ecrc_dw_offset, 4, ENC_LITTLE_ENDIAN, &ecrc);

        // Calculate a partial CRC on DW0, which first needs to be modified to set all the bits in fields defined as "Variant".
        uint32_t modified_dw0 = tvb_get_ntohl(tvb, 0) | 0x01004000;
        uint8_t modified_dw0_buf[] = { modified_dw0 >> 24, modified_dw0 >> 16, modified_dw0 >> 8, modified_dw0 };
        uint32_t crc_seed = crc32_ccitt_seed(modified_dw0_buf, 4, CRC32_CCITT_SEED) ^ 0xFFFFFFFF;

        // Validate the CRC.
        if (ecrc != crc32_ccitt_tvb_offset_seed(tvb, 4, 4*ecrc_dw_offset-4, crc_seed)) {
            expert_add_info(pinfo, ecrc_item, &EI_PCIE_TLP_ECRC_INVALID);
        }
    }

    proto_item_set_generated(proto_tree_add_uint_format_value(tlp_tree, HF_PCIE_TLP_TAG, tvb, 0, 0, tlp_tag, "0x%03x", tlp_tag));

    if (tlp_trans) {
        if ((!is_completion(tlp_fmt_type)) && (!is_posted_request(tlp_fmt_type))) {
            /* This is a request */
            if (tlp_trans->cpl_frame) {
                proto_item * it = proto_tree_add_uint(tlp_tree, HF_PCIE_TLP_COMPLETION_IN, tvb, 0, 0, tlp_trans->cpl_frame);
                proto_item_set_generated(it);
            }
        } else if (is_completion(tlp_fmt_type)) {
            /* This is a completion */
            if (tlp_trans->req_frame) {
                proto_item * it;

                it = proto_tree_add_uint(tlp_tree, HF_PCIE_TLP_REQUEST_IN, tvb, 0, 0, tlp_trans->req_frame);
                proto_item_set_generated(it);

                nstime_t ns;
                nstime_delta(&ns, &pinfo->fd->abs_ts, &tlp_trans->req_time);

                it = proto_tree_add_time(tlp_tree, HF_PCIE_TLP_COMPLETION_TIME, tvb, 0, 0, &ns);
                proto_item_set_generated(it);
            }
        }
    }

    return tvb_captured_length(tvb);
}

static void dissect_tlp_req_id(proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t *req_id, tlp_bdf_t *req_bdf) {
    proto_item * req_id_item = proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_REQ_ID, tvb, offset, 2, ENC_BIG_ENDIAN, req_id);
    proto_tree * req_id_tree = proto_item_add_subtree(req_id_item, ETT_PCIE_TLP_REQ_ID);
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_BUS, tvb, offset, 2, ENC_BIG_ENDIAN, &req_bdf->bus);
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_DEV, tvb, offset, 2, ENC_BIG_ENDIAN, &req_bdf->dev);
    proto_tree_add_item_ret_uint(req_id_tree, HF_PCIE_TLP_REQ_FUN, tvb, offset, 2, ENC_BIG_ENDIAN, &req_bdf->fun);

    proto_item_set_text(req_id_item, "Requester ID: %02x:%02x.%x (0x%04x)", req_bdf->bus, req_bdf->dev, req_bdf->fun, *req_id);
}

static void dissect_tlp_cpl_id(proto_tree *tree, tvbuff_t *tvb, int offset, tlp_bdf_t *cpl_bdf) {
    uint32_t cpl_id = 0;
    proto_item * cpl_id_item = proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_CPL_ID, tvb, offset, 2, ENC_BIG_ENDIAN, &cpl_id);
    proto_tree * cpl_id_tree = proto_item_add_subtree(cpl_id_item, ETT_PCIE_TLP_CPL_ID);
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_BUS, tvb, offset, 2, ENC_BIG_ENDIAN, &cpl_bdf->bus);
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_DEV, tvb, offset, 2, ENC_BIG_ENDIAN, &cpl_bdf->dev);
    proto_tree_add_item_ret_uint(cpl_id_tree, HF_PCIE_TLP_CPL_FUN, tvb, offset, 2, ENC_BIG_ENDIAN, &cpl_bdf->fun);

    proto_item_set_text(cpl_id_item, "Completer ID: %02x:%02x.%x (0x%04x)", cpl_bdf->bus, cpl_bdf->dev, cpl_bdf->fun, cpl_id);
}

static void dissect_tlp_req_id_and_tag70(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70) {
    tlp_bdf_t req_bdf = {0};
    dissect_tlp_req_id(tree, tvb, 4, req_id, &req_bdf);

    col_clear(pinfo->cinfo, COL_DEF_SRC);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%02x:%02x.%x", req_bdf.bus, req_bdf.dev, req_bdf.fun);

    proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_TAG_7_0, tvb, 6, 1, ENC_BIG_ENDIAN, tag70);
}

static void dissect_tlp_req_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70) {
    dissect_tlp_req_id_and_tag70(tvb, pinfo, tree, data, req_id, tag70);

    proto_item * dw_be_item = proto_tree_add_item(tree, HF_PCIE_TLP_LAST_FIRST_DW_BE, tvb, 7, 1, ENC_BIG_ENDIAN);
    proto_tree * dw_be_tree = proto_item_add_subtree(dw_be_item, ETT_PCIE_TLP_LAST_FIRST_DW_BE);
    proto_tree_add_item(dw_be_tree, HF_PCIE_TLP_LAST_DW_BE, tvb, 7, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dw_be_tree, HF_PCIE_TLP_FIRST_DW_BE, tvb, 7, 1, ENC_BIG_ENDIAN);
}

static void dissect_tlp_mem_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70, bool addr64) {
    dissect_tlp_req_header(tvb, pinfo, tree, data, req_id, tag70);

    if (addr64) {
        uint64_t addr_ph = 0;
        proto_item * addr_ph_item = proto_tree_add_item_ret_uint64(tree, HF_PCIE_TLP_ADDR_PH_64, tvb, 8, 8, ENC_BIG_ENDIAN, &addr_ph);
        proto_tree * addr_ph_tree = proto_item_add_subtree(addr_ph_item, ETT_PCIE_TLP_ADDR_PH);

        uint64_t addr = addr_ph & 0xFFFFFFFFFFFFFFFC;
        proto_tree_add_uint64(addr_ph_tree, HF_PCIE_TLP_ADDR_64, tvb, 8, 8, addr);

        uint32_t ph = 0;
        proto_tree_add_item_ret_uint(addr_ph_tree, HF_PCIE_TLP_PH, tvb, 8+7, 1, ENC_BIG_ENDIAN, &ph);

        proto_item_set_text(addr_ph_item, "Address: 0x%016lx, PH: %s (%d)", addr, try_val_to_str(ph, TLP_PROCESSING_HINT), ph);

        col_append_fstr(pinfo->cinfo, COL_INFO, " @ 0x%016lx", addr);

        col_clear(pinfo->cinfo, COL_DEF_DST);
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%016lx", addr);
    } else {
        uint32_t addr_ph = 0;
        proto_item * addr_ph_item = proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_ADDR_PH_32, tvb, 8, 4, ENC_BIG_ENDIAN, &addr_ph);
        proto_tree * addr_ph_tree = proto_item_add_subtree(addr_ph_item, ETT_PCIE_TLP_ADDR_PH);

        uint32_t addr = addr_ph & 0xFFFFFFFC;
        proto_tree_add_uint(addr_ph_tree, HF_PCIE_TLP_ADDR_32, tvb, 8, 4, addr);

        uint32_t ph = 0;
        proto_tree_add_item_ret_uint(addr_ph_tree, HF_PCIE_TLP_PH, tvb, 8+3, 1, ENC_BIG_ENDIAN, &ph);

        proto_item_set_text(addr_ph_item, "Address: 0x%08x, PH: %s (%d)", addr, try_val_to_str(ph, TLP_PROCESSING_HINT), ph);

        col_append_fstr(pinfo->cinfo, COL_INFO, " @ 0x%08x", addr);

        col_clear(pinfo->cinfo, COL_DEF_DST);
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08x", addr);
    }
}

static void dissect_tlp_io_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70) {
    dissect_tlp_req_header(tvb, pinfo, tree, data, req_id, tag70);

    uint32_t addr = 0;
    proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_ADDR_32, tvb, 8, 4, ENC_BIG_ENDIAN, &addr);

    col_append_fstr(pinfo->cinfo, COL_INFO, " @ 0x%08x", addr);

    col_clear(pinfo->cinfo, COL_DEF_DST);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08x", addr);
}

static void dissect_tlp_cfg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70) {
    dissect_tlp_req_header(tvb, pinfo, tree, data, req_id, tag70);

    tlp_bdf_t cpl_bdf = {0};
    dissect_tlp_cpl_id(tree, tvb, 8, &cpl_bdf);

    col_clear(pinfo->cinfo, COL_DEF_DST);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%02x:%02x.%x", cpl_bdf.bus, cpl_bdf.dev, cpl_bdf.fun);

    uint32_t reg_num = 0;
    proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_REG, tvb, 10, 2, ENC_BIG_ENDIAN, &reg_num);

    col_append_fstr(pinfo->cinfo, COL_INFO, " @ 0x%03x", 4*reg_num);
}

static void dissect_tlp_msg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70) {
    dissect_tlp_req_id_and_tag70(tvb, pinfo, tree, data, req_id, tag70);

    proto_tree_add_item(tree, HF_PCIE_TLP_MSG_CODE, tvb, 7, 1, ENC_BIG_ENDIAN);
}

static void dissect_tlp_cpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t *req_id, uint32_t *tag70) {
    tlp_bdf_t cpl_bdf = {0};
    dissect_tlp_cpl_id(tree, tvb, 4, &cpl_bdf);

    col_clear(pinfo->cinfo, COL_DEF_SRC);
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%02x:%02x.%x", cpl_bdf.bus, cpl_bdf.dev, cpl_bdf.fun);

    proto_item * status_bcm_byte_count_item = proto_tree_add_item(tree, HF_PCIE_TLP_CPL_STATUS_BCM_BYTE_COUNT, tvb, 6, 2, ENC_BIG_ENDIAN);
    proto_tree * status_bcm_byte_count_tree = proto_item_add_subtree(status_bcm_byte_count_item, ETT_PCIE_TLP_CPL_STATUS_BCM_BYTE_COUNT);

    uint32_t status = 0;
    proto_item * status_item = proto_tree_add_item_ret_uint(status_bcm_byte_count_tree, HF_PCIE_TLP_CPL_STATUS, tvb, 6, 2, ENC_BIG_ENDIAN, &status);
    if (status != 0) {
        expert_add_info(pinfo, status_item, &EI_PCIE_TLP_CPL_STATUS_NOT_SUCCESSFUL);
    }

    const char * status_str = try_val_to_str(status, TLP_CPL_STATUS_SHORT);
    if (status_str == NULL) {
        status_str = "Invalid Completion Status";
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", status_str);

    gboolean bcm = false;
    proto_tree_add_item_ret_boolean(status_bcm_byte_count_tree, HF_PCIE_TLP_CPL_BCM, tvb, 6, 2, ENC_BIG_ENDIAN, &bcm);

    uint32_t byte_count = 0;
    proto_tree_add_item_ret_uint(status_bcm_byte_count_tree, HF_PCIE_TLP_CPL_BYTE_COUNT, tvb, 6, 2, ENC_BIG_ENDIAN, &byte_count);

    proto_item_set_text(status_bcm_byte_count_item, "Completion Status: %s, BCM: %s, Byte Count: %d", status_str, bcm ? "True" : "False", byte_count);

    tlp_bdf_t req_bdf = {0};
    dissect_tlp_req_id(tree, tvb, 8, req_id, &req_bdf);

    col_clear(pinfo->cinfo, COL_DEF_DST);
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%02x:%02x.%x", req_bdf.bus, req_bdf.dev, req_bdf.fun);

    proto_tree_add_item_ret_uint(tree, HF_PCIE_TLP_TAG_7_0, tvb, 10, 1, ENC_BIG_ENDIAN, tag70);
    proto_tree_add_item(tree, HF_PCIE_TLP_CPL_LOWER_ADDR, tvb, 11, 1, ENC_BIG_ENDIAN);
}

static void proto_register_pcie_capture() {
    PROTO_PCIE = proto_register_protocol(
        "PCI Express Capture",
        "PCIe",
        "pcie"
    );

    proto_register_field_array(PROTO_PCIE, HF_PCIE, array_length(HF_PCIE));

    expert_module_t * expert = expert_register_protocol(PROTO_PCIE);
    expert_register_field_array(expert, EI_PCIE, array_length(EI_PCIE));

    PCIE_HANDLE = register_dissector("pcie", dissect_pcie, PROTO_PCIE);
}

static void proto_register_pcie_frame() {
    PROTO_PCIE_FRAME = proto_register_protocol(
        "PCI Express Frame",
        "PCIe Frame",
        "pcie.frame"
    );

    proto_register_field_array(PROTO_PCIE_FRAME, HF_PCIE_FRAME, array_length(HF_PCIE_FRAME));

    expert_module_t * expert = expert_register_protocol(PROTO_PCIE_FRAME);
    expert_register_field_array(expert, EI_PCIE_FRAME, array_length(EI_PCIE_FRAME));

    PCIE_FRAME_HANDLE = register_dissector("pcie.frame", dissect_pcie_frame, PROTO_PCIE_FRAME);
}

static void proto_register_pcie_dllp() {
    PROTO_PCIE_DLLP = proto_register_protocol(
        "PCI Express Data Link Layer Packet",
        "PCIe DLLP",
        "pcie.dllp"
    );

    proto_register_field_array(PROTO_PCIE_DLLP, HF_PCIE_DLLP, array_length(HF_PCIE_DLLP));

    expert_module_t * expert = expert_register_protocol(PROTO_PCIE_DLLP);
    expert_register_field_array(expert, EI_PCIE_DLLP, array_length(EI_PCIE_DLLP));

    PCIE_DLLP_HANDLE = register_dissector("pcie.dllp", dissect_pcie_dllp, PROTO_PCIE_DLLP);
}

static void proto_register_pcie_tlp() {
    PROTO_PCIE_TLP = proto_register_protocol(
        "PCI Express Transaction Layer Packet",
        "PCIe TLP",
        "pcie.tlp"
    );

    proto_register_field_array(PROTO_PCIE_TLP, HF_PCIE_TLP, array_length(HF_PCIE_TLP));

    expert_module_t * expert = expert_register_protocol(PROTO_PCIE_TLP);
    expert_register_field_array(expert, EI_PCIE_TLP, array_length(EI_PCIE_TLP));

    PCIE_TLP_HANDLE = register_dissector("pcie.tlp", dissect_pcie_tlp, PROTO_PCIE_TLP);
}

void proto_register_pcie() {
    proto_register_subtree_array(ETT, array_length(ETT));

    // PCIe Capture
    proto_register_pcie_capture();

    // PCIe Frame
    proto_register_pcie_frame();

    // PCIe DLLP
    proto_register_pcie_dllp();

    // PCIe TLP
    proto_register_pcie_tlp();
}

void proto_reg_handoff_pcie() {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER11, PCIE_HANDLE);
}
