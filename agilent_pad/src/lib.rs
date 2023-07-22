// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *  src/lib.rs - Parser library for Agilent PAD files.
 *  Copyright (C) 2023  Forest Crossman <cyrozap@gmail.com>
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

use nom::bytes::streaming::take;
use nom::multi::{count, length_data};
use nom::number::streaming::{be_u16, be_u32, be_u64, le_u16, le_u32};
use nom::sequence::tuple;
use nom::IResult;

fn u32_hi_lo_to_u64(hi: u32, lo: u32) -> u64 {
    (<u32 as Into<u64>>::into(hi).checked_shl(32).unwrap()) | <u32 as Into<u64>>::into(lo)
}

#[derive(Debug)]
pub struct Record {
    pub number: u32,
    pub data_len: u32,
    pub count: u64,
    pub timestamp_ns: u64,
    pub unk3: [u8; 2],
    pub data_valid: bool,
    pub data_valid_count: u16,
    pub flags: u32,
    pub data_offset: u64,
}

fn le_u32_typed(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
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
            take(2usize),
            le_u16,
            le_u32,
            le_u32,
            le_u32,
        ))(input)
        {
            Ok((_, o)) => Some(Self {
                number: o.0,
                data_len: o.1,
                count: u32_hi_lo_to_u64(o.2, o.3),
                timestamp_ns: u32_hi_lo_to_u64(o.4, o.5),
                unk3: o.6.try_into().unwrap(),
                data_valid: (o.7 & 0x8000) != 0,
                data_valid_count: o.7 & 0x7FFF,
                flags: o.8,
                data_offset: u32_hi_lo_to_u64(o.9, o.10),
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
    pub fn from_slice(input: &[u16]) -> Self {
        Self {
            hour: input[0],
            minute: input[1],
            millisec: input[2],
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
    pub numbers0: Vec<u32>,
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

pub fn parse_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(be_u16)(input)
}

pub fn parse_header(pad_file: &mut File) -> Option<PadHeader> {
    let mut pad_reader = BufReader::new(pad_file);
    let mut buffer: Vec<u8> = vec![0; 0];
    let mut expand: usize = 0;
    loop {
        buffer.resize_with(buffer.len() + expand, Default::default);
        pad_reader.read_exact(buffer.as_mut_slice()).unwrap();
        //println!("bytes read: {}", bytes_read);
        match tuple((
            count(parse_string, 5),
            count(be_u32, 2),
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
            count(parse_string, 2),
            count(be_u16, 6),
            be_u64,
            be_u64,
            parse_string,
        ))(buffer.as_slice())
        {
            Ok((_, o)) => {
                return Some(PadHeader {
                    module_type: String::from_utf8_lossy(o.0[0]).into(),
                    port_id: String::from_utf8_lossy(o.0[1]).into(),
                    rx_or_tx: String::from_utf8_lossy(o.0[2]).into(),
                    description: String::from_utf8_lossy(o.0[3]).into(),
                    format_code: String::from_utf8_lossy(o.0[4]).into(),
                    numbers0: o.1,
                    trigger_record_number: o.2,
                    three: o.3,
                    first_record_number: o.4,
                    last_record_number: o.5,
                    record_len: o.6,
                    timestamp_array_size: o.7,
                    timestamps_ns: TimestampsNs {
                        first: o.8,
                        last: o.9,
                        stop: o.10,
                        trigger: o.11,
                    },
                    guid: String::from_utf8_lossy(o.12).into(),
                    channel_names: ChannelNames {
                        a: String::from_utf8_lossy(o.13[0]).into(),
                        b: String::from_utf8_lossy(o.13[1]).into(),
                    },
                    start_time: CoarseTimestamp::from_slice(&o.14[..3]),
                    stop_time: CoarseTimestamp::from_slice(&o.14[3..]),
                    records_offset: o.15,
                    record_data_offset: o.16,
                    start: String::from_utf8_lossy(o.17).into(),
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
