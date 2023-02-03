// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *  parse.rs - Parser demo for Agilent PAD files.
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

use clap::Parser;

use agilent_pad::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The PAD file to read.
    pad_file: String,
}

fn get_bit(value: u32, bit: usize) -> bool {
    value & (1 << bit) != 0
}

fn char_for_nybble(value: u8) -> char {
    match value {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        0xa => 'a',
        0xb => 'b',
        0xc => 'c',
        0xd => 'd',
        0xe => 'e',
        0xf => 'f',
        _ => '?',
    }
}

fn main() {
    let args = Args::parse();

    let mut pad_file = match File::open(&args.pad_file) {
        Ok(f) => f,
        Err(error) => {
            eprintln!("Error opening file {:?}: {:?}", &args.pad_file, error);
            return;
        }
    };

    let mut pad_file_2 = match File::open(&args.pad_file) {
        Ok(f) => f,
        Err(error) => {
            eprintln!("Error opening file {:?}: {:?}", &args.pad_file, error);
            return;
        }
    };

    let header = parse_header(&mut pad_file).unwrap();
    println!("{:?}", header);

    let first_record_number = header.0.numbers[4];
    let last_record_number = header.0.numbers[5];
    let record_data_offset = header.0.numbers2[6];

    pad_file.seek(std::io::SeekFrom::Start(header.1)).unwrap();
    let mut pad_reader = BufReader::new(pad_file);

    pad_file_2
        .seek(std::io::SeekFrom::Start(record_data_offset.into()))
        .unwrap();
    let mut data_reader = BufReader::new(pad_file_2);

    let mut prev_timestamp_ns = None;
    let mut current_offset: i64 = 0;
    for record_number in first_record_number..=last_record_number {
        let mut record_buffer = vec![0; 40];
        pad_reader.read_exact(record_buffer.as_mut_slice()).unwrap();
        let record = Record::from_slice(record_buffer.as_slice()).unwrap();
        if record.number == 0 && record.timestamp_ns == 0 && record.data_len == 0 {
            println!("Encountered empty record, exiting...");
            break;
        }

        assert_eq!(record.number, record_number);

        let us_ds = match get_bit(record.flags, 28) {
            true => "US",
            false => "DS",
        };

        let ts_ns_int = record.timestamp_ns / 1000000000;
        let ts_ns_frac = record.timestamp_ns % 1000000000;

        if prev_timestamp_ns.is_none() {
            prev_timestamp_ns = Some(record.timestamp_ns);
        }

        let record_data = if record.data_valid {
            data_reader
                .seek_relative(<u32 as Into<i64>>::into(record.data_offset) - current_offset)
                .unwrap();
            let mut data: Vec<u8> = vec![0; record.data_valid_count.into()];
            data_reader.read_exact(data.as_mut_slice()).unwrap();
            current_offset = <u32 as Into<i64>>::into(record.data_offset)
                + <usize as TryInto<i64>>::try_into(data.len()).unwrap();

            let mut ret = String::with_capacity(2 + 2 * data.len());
            ret.push_str(": ");
            for b in data.iter() {
                ret.push(char_for_nybble(b >> 4));
                ret.push(char_for_nybble(b & 0xf));
            }
            ret
        } else {
            "".to_string()
        };

        let debug_data = format!(
            " (unk0: 0x{:08x}, unk1: 0x{:08x}, unk2: 0x{:08x}, unk3: {:02x}{:02x}, bytes_valid: {} ({}), flags: 0x{:08x}, data_offset: {})",
            record.unk0,
            record.unk1,
            record.unk2,
            record.unk3[0],
            record.unk3[1],
            record.data_valid_count,
            match record.data_valid {
                true => 1,
                false => 0,
            },
            record.flags,
            record.data_offset,
        );

        println!(
            "{} Record {} @ {}.{:09}s (+{}ns){}{}",
            us_ds,
            record.number,
            ts_ns_int,
            ts_ns_frac,
            record
                .timestamp_ns
                .saturating_sub(prev_timestamp_ns.unwrap()),
            debug_data,
            record_data,
        );

        prev_timestamp_ns = Some(record.timestamp_ns);
    }
}
