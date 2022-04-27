#!/usr/bin/env python3

import argparse
import sys

try:
    import agilent_pad
except ModuleNotFoundError:
    sys.stderr.write("Error: Failed to import \"agilent_pad.py\". Please run \"make\" in this directory to generate that file, then try running this script again.\n")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
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
        ts_ns_int = record.timestamp_ns // 1000000000
        ts_ns_frac = record.timestamp_ns % 1000000000
        print("Record {} @ {}.{:09d}s: {}".format(
            record.number, ts_ns_int, ts_ns_frac, pad_stream.read(record.data_length).hex()))


if __name__ == "__main__":
    sys.exit(main())
