#!/usr/bin/env python3

import argparse
import sys

try:
    import agilent_pad
except ModuleNotFoundError:
    sys.stderr.write("Error: Failed to import \"agilent_pad.py\". Please run \"make\" in this directory to generate that file, then try running this script again.\n")
    sys.exit(1)


TLP_TYPES = (
    # (fmt mask, fmt, type mask, type, name, description)
    (0b110, 0b000, 0b11111, 0b00000, "MRd", ""),
    (0b110, 0b000, 0b11111, 0b00001, "MRdLk", ""),
    (0b110, 0b010, 0b11111, 0b00000, "MWr", ""),
    (0b111, 0b000, 0b11111, 0b00010, "IORd", ""),
    (0b111, 0b010, 0b11111, 0b00010, "IOWr", ""),
    (0b111, 0b000, 0b11111, 0b00100, "CfgRd0", ""),
    (0b111, 0b010, 0b11111, 0b00100, "CfgWr0", ""),
    (0b111, 0b000, 0b11111, 0b00101, "CfgRd1", ""),
    (0b111, 0b010, 0b11111, 0b00101, "CfgWr1", ""),
    (0b111, 0b000, 0b11111, 0b11011, "TCfgRd", ""),
    (0b111, 0b010, 0b11111, 0b11011, "TCfgWr", ""),
    (0b111, 0b001, 0b11000, 0b10000, "Msg", ""),
    (0b111, 0b011, 0b11000, 0b10000, "MsgD", ""),
    (0b111, 0b000, 0b11111, 0b01010, "Cpl", ""),
    (0b111, 0b010, 0b11111, 0b01010, "CplD", ""),
    (0b111, 0b000, 0b11111, 0b01011, "CplLk", ""),
    (0b111, 0b010, 0b11111, 0b01011, "CplDLk", ""),
    (0b110, 0b010, 0b11111, 0b01100, "FetchAdd", ""),
    (0b110, 0b010, 0b11111, 0b01101, "Swap", ""),
    (0b110, 0b010, 0b11111, 0b01110, "CAS", ""),
    (0b111, 0b100, 0b10000, 0b00000, "LPrfx", ""),
    (0b111, 0b100, 0b10000, 0b10000, "EPrfx", ""),
)


def get_bit(value : int, bit : int):
    return True if (value & (1 << bit)) != 0 else False

def get_tlp_type_string(tlp):
    for fmask, tfmt, tmask, ttype, name, desc in TLP_TYPES:
        if tfmt == (fmask & tlp.header.fmt.value) and ttype == (tmask & tlp.header.type):
            return name, desc

    return "Unk", "Unknown"

def get_string_for_tlp(tlp):
    tlp_type_name, tlp_type_desc = get_tlp_type_string(tlp)

    data = b''
    if "data" in dir(tlp):
        data = tlp.data

    data_string = ""
    if data:
        data_string = ", Data: {}".format(data.hex())

    addr_fmt = "0x{:08x}"
    if tlp.header.fmt.value & 1:
        addr_fmt = "0x{:016x}"

    return "TLP: {{ Type: {}, Address: {}{} }}".format(tlp_type_name, addr_fmt.format(tlp.address), data_string)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", default=False, action="store_true", help="Enable debug output.")
    parser.add_argument("-l", "--dllp", default=False, action="store_true", help="Display DLLP info.")
    parser.add_argument("-t", "--tlp", default=False, action="store_true", help="Display TLP info.")
    parser.add_argument("-e", "--filter-errors", default=False, action="store_true", help="Filter out records with errors.")
    parser.add_argument("pad_file", type=str, help="The Protocol Analyzer Data (.pad) file.")
    args = parser.parse_args()

    pad = agilent_pad.AgilentPad.from_file(args.pad_file)
    pad_stream = open(args.pad_file, 'rb')
    pad_stream.seek(pad.record_data_offset)
    io = pad._io
    while io.pos() < pad.record_data_offset - 40:
        record = agilent_pad.AgilentPad.Record(io, pad, pad)
        if record.number == 0 and record.timestamp_ns == 0 and record.data_length == 0:
            print("Encountered empty record, exiting...")
            break
        record_data = pad_stream.read(record.data_length)

        ts_ns_int = record.timestamp_ns // 1000000000
        ts_ns_frac = record.timestamp_ns % 1000000000
        bytes_valid = record.bytes_valid & 0x7ff
        bytes_valid_flag = record.bytes_valid >> 15

        valid_data = record_data[:bytes_valid]

        if args.filter_errors:
            if get_bit(record.flags, 3):
                # Symbol Error
                continue
            if get_bit(record.flags, 11):
                # Disparity Error
                continue

        debug_data = ""
        if args.debug:
            debug_data = " (unk1: 0x{:08x}, unk2: 0x{:08x}, unk3: {}, bytes_valid: {} ({}), flags: 0x{:08x}, byte_counter: {})".format(
                record.unk1, record.unk2, record.unk3.hex(),
                bytes_valid, bytes_valid_flag, record.flags,
                record.byte_counter, valid_data.hex())

        dllp = None
        if args.dllp or args.tlp:
            if valid_data and valid_data[0] == 0xfb:
                try:
                    dllp = agilent_pad.AgilentPad.Dllp.from_bytes(valid_data)
                    dllp_size = dllp._io.pos()
                except:
                    pass
            if not (dllp and dllp.end_tag == 0xfd):
                continue

            tlp_data = get_string_for_tlp(dllp.tlp)

        display_data = ""
        if args.dllp:
            display_data = "DLLP: {{ TLP Seq. No.: {}, {}, LCRC: 0x{:08x} }}".format(dllp.tlp_sequence_number, tlp_data, dllp.lcrc)
        elif args.tlp:
            display_data = tlp_data
        else:
            display_data = valid_data.hex()

        print("{} Record {} @ {}.{:09d}s{}: {}".format(
            "US" if get_bit(record.flags, 28) else "DS",
            record.number, ts_ns_int, ts_ns_frac,
            debug_data, display_data))


if __name__ == "__main__":
    sys.exit(main())
