# agilent\_pad

A Rust library for parsing Agilent PAD files. The included examples can be used
to decode a PAD file and print the parsed data to the terminal or convert the
file to PCAP-NG format.


## How to use

To parse a PAD file:

- `cargo run --release --example parse PAD_FILE.pad | less -S`

To convert a PAD file to PCAP-NG:

- `cargo run --release --example pad2pcapng PAD_FILE.pad PCAPNG_FILE.pcapng`

Once converted, the PCAP-NG file can be used with the
[Wireshark PCIe dissector][dissector].


## License

[GNU General Public License, version 3 or later][license].


[dissector]: ../../wireshark
[license]: ../../COPYING.txt
