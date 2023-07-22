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
pub struct PadHeader {
    pub strings: Vec<String>,
    pub numbers0: Vec<u32>,
    pub trigger_record_number: u32,
    pub three: u32,
    pub first_record_number: u32,
    pub last_record_number: u32,
    pub record_len: u32,
    pub timestamp_array_size: u32,
    pub timestamps_ns: Vec<u64>,
    pub trigger_timestamp_ns: u64,
    pub guid: String,
    pub channels: Vec<String>,
    pub numbers2: Vec<u32>,
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
            count(be_u64, 3),
            be_u64,
            parse_string,
            count(parse_string, 2),
            count(be_u32, 3),
            be_u64,
            be_u64,
            parse_string,
        ))(buffer.as_slice())
        {
            Ok((_, o)) => {
                return Some(PadHeader {
                    strings: o
                        .0
                        .into_iter()
                        .map(|b| String::from_utf8_lossy(b).into())
                        .collect::<Vec<_>>(),
                    numbers0: o.1,
                    trigger_record_number: o.2,
                    three: o.3,
                    first_record_number: o.4,
                    last_record_number: o.5,
                    record_len: o.6,
                    timestamp_array_size: o.7,
                    timestamps_ns: o.8,
                    trigger_timestamp_ns: o.9,
                    guid: String::from_utf8_lossy(o.10).into(),
                    channels: o
                        .11
                        .into_iter()
                        .map(|b| String::from_utf8_lossy(b).into())
                        .collect::<Vec<_>>(),
                    numbers2: o.12,
                    records_offset: o.13,
                    record_data_offset: o.14,
                    start: String::from_utf8_lossy(o.15).into(),
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
