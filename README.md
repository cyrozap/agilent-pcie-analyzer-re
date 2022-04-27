# Agilent PCIe Protocol Analyzer Reverse Engineering

Reverse engineering the N5305A/N5306A family of PCIe protocol analyzers and
their host software.


## Quick start

### Software dependencies

* Python 3
* [Kaitai Struct Compiler][ksc]
* [Kaitai Struct Python Runtime][kspr]

### Procedure

1. Install dependencies.
2. Run `make` to generate the parser code used by `cap_tool.py`.
3. Run `./cap_tool.py` on a `*.pad` protocol analyzer data file.


## Related projects

* [Nox][nox]: A set of FOSS tools, utilities, and libraries for PCI-Express
  analyzers.


[nox]: https://github.com/lethalbit/Nox
