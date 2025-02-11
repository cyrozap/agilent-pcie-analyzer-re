// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *  src/lib.rs - Parser library for Agilent PAD files.
 *  Copyright (C) 2023-2024  Forest Crossman <cyrozap@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

use nom::multi::length_data;
use nom::number::streaming::{be_u16, be_u32, be_u64, le_u16, le_u32};
use nom::sequence::tuple;
use nom::IResult;

fn u32_hi_lo_to_u64(hi: u32, lo: u32) -> u64 {
    (<u32 as Into<u64>>::into(hi).checked_shl(u32::BITS).unwrap()) | <u32 as Into<u64>>::into(lo)
}

fn le_u32_typed(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
}

fn parse_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(be_u16)(input)
}

#[derive(Debug)]
pub struct Record {
    pub number: u32,
    pub data_len: u32,
    pub count: u64,
    pub timestamp_ns: u64,
    pub lfsr: u16,
    pub extra_metadata_present: bool,
    pub metadata_offset: u16,
    pub flags: u32,
    pub data_offset: u64,
}

impl Record {
    pub fn from_slice(input: &[u8]) -> Option<Self> {
        match tuple((
            le_u32_typed,
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u16,
            le_u16,
            le_u32,
            le_u32,
            le_u32,
        ))(input)
        {
            Ok((
                _,
                (
                    number,
                    data_len,
                    count_hi,
                    count_lo,
                    timestamp_ns_hi,
                    timestamp_ns_lo,
                    lfsr,
                    metadata_info,
                    flags,
                    data_offset_hi,
                    data_offset_lo,
                ),
            )) => Some(Self {
                number,
                data_len,
                count: u32_hi_lo_to_u64(count_hi, count_lo),
                timestamp_ns: u32_hi_lo_to_u64(timestamp_ns_hi, timestamp_ns_lo),
                lfsr,
                extra_metadata_present: (metadata_info & 0x8000) != 0,
                metadata_offset: metadata_info & 0x7FFF,
                flags,
                data_offset: u32_hi_lo_to_u64(data_offset_hi, data_offset_lo),
            }),
            Err(e) => panic!("{:?}", e),
        }
    }
}

#[derive(Debug)]
pub struct TimestampsNs {
    pub first: u64,
    pub last: u64,
    pub stop: u64,
    pub trigger: u64,
}

#[derive(Debug)]
pub struct ChannelNames {
    pub a: String,
    pub b: String,
}

#[derive(Debug)]
pub struct CoarseTimestamp {
    pub hour: u16,
    pub minute: u16,
    pub millisec: u16,
}

impl CoarseTimestamp {
    pub fn from_tuple(input: (u16, u16, u16)) -> Self {
        Self {
            hour: input.0,
            minute: input.1,
            millisec: input.2,
        }
    }

    pub fn is_null(&self) -> bool {
        self.hour == 0 && self.minute == 0 && self.millisec == 0
    }
}

#[derive(Debug)]
pub struct PadHeader {
    pub module_type: String,
    pub port_id: String,
    pub rx_or_tx: String,
    pub description: String,
    pub format_code: String,
    pub numbers0: (u32, u32),
    pub trigger_record_number: u32,
    pub three: u32,
    pub first_record_number: u32,
    pub last_record_number: u32,
    pub record_len: u32,
    pub timestamp_array_size: u32,
    pub timestamps_ns: TimestampsNs,
    pub guid: String,
    pub channel_names: ChannelNames,
    pub start_time: CoarseTimestamp,
    pub stop_time: CoarseTimestamp,
    pub records_offset: u64,
    pub record_data_offset: u64,
    pub start: String,
}

impl PadHeader {
    pub fn from_bufreader<R>(pad_reader: &mut BufReader<R>) -> Option<Self>
    where
        R: Read + Seek,
    {
        let mut buffer: Vec<u8> = vec![0; 0];
        let mut expand: usize = 0;
        loop {
            buffer.resize_with(buffer.len() + expand, Default::default);
            pad_reader.read_exact(buffer.as_mut_slice()).unwrap();
            //println!("bytes read: {}", bytes_read);
            match tuple((
                tuple((
                    parse_string,
                    parse_string,
                    parse_string,
                    parse_string,
                    parse_string,
                )),
                tuple((be_u32, be_u32)),
                be_u32,
                be_u32,
                be_u32,
                be_u32,
                be_u32,
                be_u32,
                be_u64,
                be_u64,
                be_u64,
                be_u64,
                parse_string,
                tuple((parse_string, parse_string)),
                tuple((be_u16, be_u16, be_u16)),
                tuple((be_u16, be_u16, be_u16)),
                be_u64,
                be_u64,
                parse_string,
            ))(buffer.as_slice())
            {
                Ok((
                    _,
                    (
                        (module_type, port_id, rx_or_tx, description, format_code),
                        numbers0,
                        trigger_record_number,
                        three,
                        first_record_number,
                        last_record_number,
                        record_len,
                        timestamp_array_size,
                        timestamps_ns_first,
                        timestamps_ns_last,
                        timestamps_ns_stop,
                        timestamps_ns_trigger,
                        guid,
                        (channel_names_a, channel_names_b),
                        start_time,
                        stop_time,
                        records_offset,
                        record_data_offset,
                        start,
                    ),
                )) => {
                    return Some(Self {
                        module_type: String::from_utf8_lossy(module_type).into(),
                        port_id: String::from_utf8_lossy(port_id).into(),
                        rx_or_tx: String::from_utf8_lossy(rx_or_tx).into(),
                        description: String::from_utf8_lossy(description).into(),
                        format_code: String::from_utf8_lossy(format_code).into(),
                        numbers0,
                        trigger_record_number,
                        three,
                        first_record_number,
                        last_record_number,
                        record_len,
                        timestamp_array_size,
                        timestamps_ns: TimestampsNs {
                            first: timestamps_ns_first,
                            last: timestamps_ns_last,
                            stop: timestamps_ns_stop,
                            trigger: timestamps_ns_trigger,
                        },
                        guid: String::from_utf8_lossy(guid).into(),
                        channel_names: ChannelNames {
                            a: String::from_utf8_lossy(channel_names_a).into(),
                            b: String::from_utf8_lossy(channel_names_b).into(),
                        },
                        start_time: CoarseTimestamp::from_tuple(start_time),
                        stop_time: CoarseTimestamp::from_tuple(stop_time),
                        records_offset,
                        record_data_offset,
                        start: String::from_utf8_lossy(start).into(),
                    })
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(n))) => expand = n.get(),
                _ => return None,
            }
            pad_reader
                .seek_relative(-(<usize as TryInto<i64>>::try_into(buffer.len()).unwrap()))
                .unwrap();
        }
    }

    pub fn from_file(pad_file: &mut File) -> Option<Self> {
        let mut pad_reader = BufReader::new(pad_file);

        Self::from_bufreader(&mut pad_reader)
    }
}

#[derive(Debug)]
pub struct Records {
    curr: u32,
    last: u32,
    reader: BufReader<File>,
}

impl Records {
    fn new(first: u32, last: u32, reader: BufReader<File>) -> Self {
        Self {
            curr: first,
            last,
            reader,
        }
    }
}

impl Iterator for Records {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr > self.last {
            return None;
        }

        let mut record_buffer = [0; 40];

        self.reader.read_exact(&mut record_buffer).unwrap();

        /* Handle null record */
        if record_buffer.iter().all(|b| *b == 0) {
            self.curr = self.last + 1;
            return None;
        }

        let record = Record::from_slice(&record_buffer).unwrap();

        assert_eq!(record.number, self.curr, "record number mismatch");

        self.curr += 1;

        Some(record)
    }
}

#[derive(Debug)]
pub struct RecordReader {
    data_reader: BufReader<File>,
    curr_data_offset: i64,
}

impl RecordReader {
    fn get_data_for_record(&mut self, record: &Record, exclude_metadata: bool) -> Vec<u8> {
        self.data_reader
            .seek_relative(
                <u64 as TryInto<i64>>::try_into(record.data_offset).unwrap()
                    - self.curr_data_offset,
            )
            .unwrap();

        let data_read_len = if exclude_metadata && record.metadata_offset > 0 {
            record.metadata_offset.into()
        } else {
            record.data_len.try_into().unwrap()
        };

        let mut buf: Vec<u8> = vec![0; data_read_len];

        self.data_reader.read_exact(buf.as_mut_slice()).unwrap();

        self.curr_data_offset = <u64 as TryInto<i64>>::try_into(record.data_offset).unwrap()
            + <usize as TryInto<i64>>::try_into(buf.len()).unwrap();

        buf
    }

    pub fn get_data_for_record_without_metadata(&mut self, record: &Record) -> Vec<u8> {
        self.get_data_for_record(record, true)
    }

    pub fn get_all_data_for_record(&mut self, record: &Record) -> Vec<u8> {
        self.get_data_for_record(record, false)
    }
}

#[derive(Debug)]
pub struct PadFile {
    pub header: PadHeader,
    pub records: Records,
    pub record_reader: RecordReader,
}

impl PadFile {
    pub fn from_filename(filename: &str) -> Result<Self, std::io::Error> {
        let mut pad_reader = match File::open(filename) {
            Ok(f) => BufReader::new(f),
            Err(e) => return Err(e),
        };

        let mut data_reader = match File::open(filename) {
            Ok(f) => BufReader::new(f),
            Err(e) => return Err(e),
        };

        let header = PadHeader::from_bufreader(&mut pad_reader).unwrap();

        assert_eq!(header.record_len, 40, "record length mismatch");
        assert_eq!(
            header.timestamp_array_size, 8,
            "timestamp array size mismatch"
        );

        pad_reader
            .seek(std::io::SeekFrom::Start(header.records_offset))
            .unwrap();

        data_reader
            .seek(std::io::SeekFrom::Start(header.record_data_offset))
            .unwrap();

        let first = header.first_record_number;
        let last = header.last_record_number;

        Ok(Self {
            header,
            records: Records::new(first, last, pad_reader),
            record_reader: RecordReader {
                data_reader,
                curr_data_offset: 0,
            },
        })
    }
}
