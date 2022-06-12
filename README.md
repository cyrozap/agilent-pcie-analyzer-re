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


## License

Except where otherwise noted:

* All software in this repository is made available under the
  [GNU General Public License, version 3 or later][gpl].
* All copyrightable content that is not software (e.g., reverse engineering
  notes, this README file, etc.) is licensed under the
  [Creative Commons Attribution-ShareAlike 4.0 International License][cc-by-sa].


[ksc]: https://github.com/kaitai-io/kaitai_struct_compiler
[kspr]: https://github.com/kaitai-io/kaitai_struct_python_runtime
[nox]: https://github.com/lethalbit/Nox
[gpl]: COPYING.txt
[cc-by-sa]: https://creativecommons.org/licenses/by-sa/4.0/
