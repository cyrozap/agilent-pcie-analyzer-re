// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *  pad2pcapng.rs - Convert Agilent PAD files to PCAP-NG.
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
use std::io::BufWriter;

use clap::Parser;

use agilent_pad::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The PAD file to read.
    pad_file: String,

    /// The pcapng file to write.
    pcapng_file: String,
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

    let header = pad_file.header;
    println!("{:?}", header);

    let mut pcapng_writer = match File::create(&args.pcapng_file) {
        Ok(f) => BufWriter::new(f),
        Err(error) => {
            eprintln!("Error opening file {:?}: {:?}", &args.pcapng_file, error);
            return;
        }
    };

    // Section Header Block
    {
        pcapng_writer
            .write_all(&(0x0a0d0d0a as u32).to_le_bytes())
            .unwrap();

        let mut sh_data: Vec<u8> = Vec::new();
        sh_data.append(&mut (0x1a2b3c4d as u32).to_le_bytes().to_vec());
        sh_data.append(&mut (0x0001 as u16).to_le_bytes().to_vec());
        sh_data.append(&mut (0x0000 as u16).to_le_bytes().to_vec());
        sh_data.append(&mut (-1 as i64).to_le_bytes().to_vec());

        let sh_len: u32 = <usize as TryInto<u32>>::try_into(sh_data.len()).unwrap() + 4 * 3;
        pcapng_writer.write_all(&sh_len.to_le_bytes()).unwrap();
        pcapng_writer.write_all(&sh_data).unwrap();
        pcapng_writer.write_all(&sh_len.to_le_bytes()).unwrap();
    }

    // Interface Description Block
    {
        pcapng_writer
            .write_all(&(0x00000001 as u32).to_le_bytes())
            .unwrap();

        let mut if_data: Vec<u8> = Vec::new();
        if_data.append(&mut (147 + 11 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (0x0000 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (0 as u32).to_le_bytes().to_vec());

        // Options
        let mut if_name = header.port_id.clone().into_bytes();
        if_data.append(&mut (2 as u16).to_le_bytes().to_vec());
        if_data.append(
            &mut <usize as TryInto<u16>>::try_into(if_name.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
        );
        if_data.append(&mut if_name);
        let padding_count = if if_data.len() % 4 != 0 {
            4 - (if_data.len() % 4)
        } else {
            0
        };
        for _ in 0..padding_count {
            if_data.push(0);
        }

        /*
        if_data.append(&mut (8 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (8 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (2e9 as u64).to_le_bytes().to_vec());
        */

        if_data.append(&mut (9 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (1 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (9 as u32).to_le_bytes().to_vec());

        let mut if_hardware = header.module_type.clone().into_bytes();
        if_data.append(&mut (15 as u16).to_le_bytes().to_vec());
        if_data.append(
            &mut <usize as TryInto<u16>>::try_into(if_hardware.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
        );
        if_data.append(&mut if_hardware);
        let padding_count = if if_data.len() % 4 != 0 {
            4 - (if_data.len() % 4)
        } else {
            0
        };
        for _ in 0..padding_count {
            if_data.push(0);
        }

        if_data.append(&mut (0 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (0 as u16).to_le_bytes().to_vec());

        let if_len: u32 = <usize as TryInto<u32>>::try_into(if_data.len()).unwrap() + 4 * 3;
        pcapng_writer.write_all(&if_len.to_le_bytes()).unwrap();
        pcapng_writer.write_all(&if_data).unwrap();
        pcapng_writer.write_all(&if_len.to_le_bytes()).unwrap();
    }

    for record in pad_file.records {
        assert_eq!(record.count, 1, "record \"count\" field is not equal to 1");

        let mut record_data = pad_file.record_reader.get_all_data_for_record(&record);

        // Enhanced Packet Block
        {
            pcapng_writer
                .write_all(&(0x00000006 as u32).to_le_bytes())
                .unwrap();

            let mut block_data: Vec<u8> = Vec::new();
            block_data.append(&mut (0 as u32).to_le_bytes().to_vec());
            block_data.append(
                &mut <u64 as TryInto<u32>>::try_into(record.timestamp_ns.checked_shr(32).unwrap())
                    .unwrap()
                    .to_le_bytes()
                    .to_vec(),
            );
            block_data.append(
                &mut <u64 as TryInto<u32>>::try_into(record.timestamp_ns & ((1 << 32) - 1))
                    .unwrap()
                    .to_le_bytes()
                    .to_vec(),
            );
            let record_data_len =
                4 + 8 + 2 + 2 + 4 + <usize as TryInto<u32>>::try_into(record_data.len()).unwrap();
            block_data.append(&mut record_data_len.to_le_bytes().to_vec());
            block_data.append(&mut record_data_len.to_le_bytes().to_vec());

            // Record metadata
            block_data.append(&mut record.number.to_le_bytes().to_vec());
            block_data.append(&mut record.timestamp_ns.to_le_bytes().to_vec());
            block_data.append(&mut record.lfsr.to_le_bytes().to_vec());
            let value: u16 = if record.data_valid { 0x8000 } else { 0 } | record.data_valid_count;
            block_data.append(&mut value.to_le_bytes().to_vec());
            block_data.append(&mut record.flags.to_le_bytes().to_vec());

            // Record data
            block_data.append(&mut record_data);
            let padding_count = if block_data.len() % 4 != 0 {
                4 - (block_data.len() % 4)
            } else {
                0
            };
            for _ in 0..padding_count {
                block_data.push(0);
            }

            if (record.number == header.trigger_record_number)
                || (record.number == header.first_record_number
                    && header.trigger_record_number < header.first_record_number)
                || (record.number == header.last_record_number
                    && header.trigger_record_number > header.last_record_number)
            {
                let mut packet_comment = if header.timestamps_ns.trigger < record.timestamp_ns {
                    let difference_ns = record.timestamp_ns - header.timestamps_ns.trigger;
                    let ts_ns_int = difference_ns / 1000000000;
                    let ts_ns_frac = difference_ns % 1000000000;
                    format!(
                        "Triggered {}.{:09}s before this record.",
                        ts_ns_int, ts_ns_frac
                    )
                } else if header.timestamps_ns.trigger == record.timestamp_ns {
                    "Triggered on this record.".to_string()
                } else {
                    let difference_ns = header.timestamps_ns.trigger - record.timestamp_ns;
                    let ts_ns_int = difference_ns / 1000000000;
                    let ts_ns_frac = difference_ns % 1000000000;
                    format!(
                        "Triggered {}.{:09}s after this record.",
                        ts_ns_int, ts_ns_frac
                    )
                }
                .into_bytes();
                block_data.append(&mut (1 as u16).to_le_bytes().to_vec());
                block_data.append(
                    &mut <usize as TryInto<u16>>::try_into(packet_comment.len())
                        .unwrap()
                        .to_le_bytes()
                        .to_vec(),
                );
                block_data.append(&mut packet_comment);
                let padding_count = if block_data.len() % 4 != 0 {
                    4 - (block_data.len() % 4)
                } else {
                    0
                };
                for _ in 0..padding_count {
                    block_data.push(0);
                }

                block_data.append(&mut (0 as u16).to_le_bytes().to_vec());
                block_data.append(&mut (0 as u16).to_le_bytes().to_vec());
            }

            let block_len: u32 =
                <usize as TryInto<u32>>::try_into(block_data.len()).unwrap() + 4 * 3;
            pcapng_writer.write_all(&block_len.to_le_bytes()).unwrap();
            pcapng_writer.write_all(&block_data).unwrap();
            pcapng_writer.write_all(&block_len.to_le_bytes()).unwrap();
        }
    }
}
