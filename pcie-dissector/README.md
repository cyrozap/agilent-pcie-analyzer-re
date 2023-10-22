# pcie-dissector

A dissector plugin for Wireshark that can decode PCI Express captures converted
to PCAP-NG format by [pad2pcapng][pad2pcapng].


## How to use

1. Build the plugin by running `make`.
2. Install the plugin for the current user by running `make install`.
3. Start Wireshark and open a PCAP-NG format PCIe capture file.


## Packet coloring rules

Some example packet coloring rules that work with this plugin can be found in
[config/pcie\_coloring\_rules.txt][coloring]. You can read more about how
coloring rules work and how to import them [here][wiki] and [here][user guide].


## License

[GNU General Public License, version 2 or later][license].


[pad2pcapng]: ../agilent_pad/examples/pad2pcapng.rs
[coloring]: config/pcie_coloring_rules.txt
[wiki]: https://gitlab.com/wireshark/wireshark/-/wikis/ColoringRules
[user guide]: https://www.wireshark.org/docs/wsug_html_chunked/ChCustColorizationSection.html
[license]: COPYING.txt
