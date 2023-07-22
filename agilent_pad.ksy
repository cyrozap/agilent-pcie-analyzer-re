meta:
  id: agilent_pad
  file-extension: pad
  title: Agilent PCIe Protocol Analyzer Data
  license: CC0-1.0
seq:
  - id: strings
    type: string
    repeat: expr
    repeat-expr: 5
  - id: unk0
    type: u4be
    repeat: expr
    repeat-expr: 2
  - id: trigger_record_number
    type: u4be
  - id: three
    type: u4be
  - id: first_record_number
    type: u4be
  - id: last_record_number
    type: u4be
  - id: unk1
    type: u4be
    repeat: expr
    repeat-expr: 2
  - id: timestamps_ns
    type: u8be
    repeat: expr
    repeat-expr: 3
  - id: trigger_timestamp_ns
    type: u8be
  - id: guid
    type: string
  - id: channels
    type: string
    repeat: expr
    repeat-expr: 2
  - id: unk2
    size: 12
  - id: records_offset
    type: u8be
  - id: record_data_offset
    type: u8be
  - id: start
    type: string
enums:
  tlp_fmt:
    0: tdw_no_data
    1: fdw_no_data
    2: tdw_with_data
    3: fdw_with_data
    4: tlp_prefix
types:
  u8le_split:
    seq:
      - id: hi
        type: u4le
      - id: lo
        type: u4le
  string:
    seq:
      - id: len
        type: u2be
      - id: str
        size: len
        type: str
        encoding: ascii
  record:
    seq:
      - id: number
        type: u4le
      - id: data_length
        type: u4le
      - id: count
        type: u8le_split
      - id: timestamp_ns
        type: u8le_split
      - id: unk3
        size: 2
      - id: bytes_valid
        type: u2le
        doc: "Bits [14:0]: The length of the sequence of valid bytes in the record data, starting from the first byte. Bit [15]: Unknown."
      - id: flags
        type: u4le
        doc: >
          Bit 3: Symbol error.
          Bit 11: Disparity error.
          Bit 28: Upstream (1), not Downstream (0).
      - id: data_offset
        type: u8le_split
        doc: "The offset of this record's data relative to `record_data_offset`."
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
        type: u4be
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
            tlp_fmt::tdw_no_data: u4be
            tlp_fmt::tdw_with_data: u4be
            tlp_fmt::fdw_no_data: u8be
            tlp_fmt::fdw_with_data: u8be
      - id: data
        size: 4 * header.len
        if: '(header.fmt == tlp_fmt::tdw_with_data) or (header.fmt == tlp_fmt::fdw_with_data)'
      - id: ecrc
        type: u4be
        if: header.td
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
        type: u2be
      - id: tag
        type: u1
      - id: last_dw_be
        type: b4
      - id: first_dw_be
        type: b4
# instances:
#   records:
#     pos: records_offset
#     type: record
#     repeat: expr
#     repeat-expr: last_record_number + 1 - first_record_number
#   dllps:
#     pos: record_data_offset
#     size-eos: true
