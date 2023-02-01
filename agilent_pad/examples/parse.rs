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

fn main() {
    let args = Args::parse();

    let mut pad_file = match File::open(&args.pad_file) {
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
    //let record_data_offset = header.0.numbers2[6];

    pad_file.seek(std::io::SeekFrom::Start(header.1)).unwrap();
    let mut pad_reader = BufReader::new(pad_file);

    let mut prev_timestamp_ns = None;
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

        println!(
            "{} Record {} @ {}.{:09}s (+{}ns) {:?}",
            us_ds,
            record.number,
            ts_ns_int,
            ts_ns_frac,
            record.timestamp_ns - prev_timestamp_ns.unwrap(),
            record
        );

        prev_timestamp_ns = Some(record.timestamp_ns);
    }
}
