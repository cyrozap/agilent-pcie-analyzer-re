#!/usr/bin/env python3

import argparse
import sys

try:
    import agilent_pad
except ModuleNotFoundError:
    sys.stderr.write("Error: Failed to import \"agilent_pad.py\". Please run \"make\" in this directory to generate that file, then try running this script again.\n")
    sys.exit(1)


def get_bit(value : int, bit : int):
    return True if (value & (1 << bit)) != 0 else False

def main():
    parser = argparse.ArgumentParser()
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

        print("Record {} @ {}.{:09d}s (unk1: 0x{:08x}, unk2: 0x{:08x}, unk3: {}, bytes_valid: {} ({}), flags: 0x{:08x}, byte_counter: {}): {}".format(
            record.number, ts_ns_int, ts_ns_frac,
            record.unk1, record.unk2, record.unk3.hex(),
            bytes_valid, bytes_valid_flag, record.flags,
            record.byte_counter, valid_data.hex()))


if __name__ == "__main__":
    sys.exit(main())
