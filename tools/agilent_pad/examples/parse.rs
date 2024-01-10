// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *  parse.rs - Parser demo for Agilent PAD files.
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

    let mut pad_file = match PadFile::from_filename(&args.pad_file) {
        Ok(pf) => pf,
        Err(error) => {
            eprintln!("Error opening file {:?}: {:?}", &args.pad_file, error);
            return;
        }
    };

    println!("{:?}", pad_file.header);

    let mut prev_timestamp_ns = None;
    for record in pad_file.records {
        let us_ds = match get_bit(record.flags, 28) {
            true => "US",
            false => "DS",
        };

        let ts_ns_int = record.timestamp_ns / 1000000000;
        let ts_ns_frac = record.timestamp_ns % 1000000000;

        if prev_timestamp_ns.is_none() {
            prev_timestamp_ns = Some(record.timestamp_ns);
        }

        let data = pad_file
            .record_reader
            .get_data_for_record_without_metadata(&record);

        let record_data = {
            let mut ret = String::with_capacity(2 + 2 * data.len());
            ret.push_str(": ");
            for b in data.iter() {
                ret.push(char_for_nybble(b >> 4));
                ret.push(char_for_nybble(b & 0xf));
            }
            ret
        };

        let debug_data = format!(
            " (count: {}, lfsr: 0x{:04x}, metadata_offset: {} ({}), flags: 0x{:08x}, data_offset: {})",
            record.count,
            record.lfsr,
            record.metadata_offset,
            match record.extra_metadata_present {
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
