# pcie-dissector

A dissector plugin for Wireshark that can decode PCI Express captures converted
to PCAP-NG format by [pad2pcapng][pad2pcapng].


## How to use

1. `make`
2. `cp pcie.so ~/.local/lib/wireshark/plugins/4.0/epan/`
3. Start Wireshark and open a PCAP-NG format PCIe capture file.


## License

[GNU General Public License, version 2 or later][license].


[pad2pcapng]: ../agilent_pad/examples/pad2pcapng.rs
[license]: COPYING.txt
