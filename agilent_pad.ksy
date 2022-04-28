meta:
  id: agilent_pad
  file-extension: pad
  endian: be
  title: Agilent PCIe Protocol Analyzer Data
  license: CC0-1.0
seq:
  - id: strings
    type: string
    repeat: expr
    repeat-expr: 5
  - id: unk0
    type: u4
    repeat: expr
    repeat-expr: 4
  - id: first_record_maybe
    type: u4
  - id: last_record_maybe
    type: u4
  - id: unk1
    type: u4
    repeat: expr
    repeat-expr: 10
  - id: guid
    type: string
  - id: ports
    type: string
    repeat: expr
    repeat-expr: 2
  - id: unk2
    size: 16+8
  - id: record_data_offset
    type: u4
  - id: start
    type: string
  # - id: records
  #   type: record
  #   repeat: expr
  #   repeat-expr: (record_data_offset-_io.pos)/40
enums:
  tlp_fmt:
    0: tdw_no_data
    1: fdw_no_data
    2: tdw_with_data
    3: fdw_with_data
    4: tlp_prefix
types:
  string:
    seq:
      - id: len
        type: u2
      - id: str
        size: len
        type: str
        encoding: ascii
  record:
    seq:
      - id: number
        type: u4le
      - id: data_length
        type: u8le
      - id: unk1
        type: u4le
      - id: unk2
        type: u4le
      - id: timestamp_ns
        type: u4le
      - id: unk3
        size: 2
      - id: bytes_valid
        type: u2le
        doc: "Bits [14:0]: The length of the sequence of valid bytes in the record data, starting from the first byte. Bit [15]: Unknown."
      - id: flags
        type: u4le
      - id: unk4
        type: u4le
      - id: byte_counter
        type: u4le
        doc: "The total number of bytes that captured up to this point, including both the valid and invalid bytes."
  dllp:
    seq:
      - id: start_tag
        type: u1
      - id: reserved
        type: b4
      - id: tlp_sequence_number
        type: b12
      - id: tlp
        type: tlp
      - id: lcrc
        type: u4
      - id: end_tag
        type: u1
  tlp:
    seq:
      - id: header
        type: tlp_header
        size: 4
      - id: next_header
        type: next_header
        size: 4
      - id: address
        type:
          switch-on: header.fmt
          cases:
            tlp_fmt::tdw_no_data: u4
            tlp_fmt::tdw_with_data: u4
            tlp_fmt::fdw_no_data: u8
            tlp_fmt::fdw_with_data: u8
      - id: data
        size: 4 * header.len
        if: '(header.fmt == tlp_fmt::tdw_with_data) or (header.fmt == tlp_fmt::fdw_with_data)'
  tlp_header:
    seq:
      - id: fmt
        type: b3
        enum: tlp_fmt
      - id: type
        type: b5
      - id: t9
        type: b1
      - id: tc
        type: b3
      - id: t8
        type: b1
      - id: attr
        type: b1
      - id: ln
        type: b1
      - id: th
        type: b1
      - id: td
        type: b1
      - id: ep
        type: b1
      - id: attr_2
        type: b2
      - id: at
        type: b2
      - id: len
        type: b10
  next_header:
    seq:
      - id: requester
        type: u2
      - id: tag
        type: u1
      - id: last_dw_be
        type: b4
      - id: first_dw_be
        type: b4
# instances:
#   dllps:
#     pos: record_data_offset
#     size-eos: true
