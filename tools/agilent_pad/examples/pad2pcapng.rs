// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *  pad2pcapng.rs - Convert Agilent PAD files to PCAP-NG.
 *  Copyright (C) 2023-2025  Forest Crossman <cyrozap@gmail.com>
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

use std::cmp::Ordering;
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

    // Only PAD files from PCIe analyzer modules are supported.
    if !matches!(
        header.module_type.as_str(),
        "AGT_MODULE_ONEPORT_PCIEXPRESS_X8"
            | "AGT_MODULE_ONEPORT_PCIEXPRESS_X16"
            | "AGT_MODULE_ONEPORT_PCIEXPRESS_GEN2"
            | "AGT_MODULE_ONEPORT_PCIEXPRESS_GEN2_X16"
            | "AGT_MODULE_ONEPORT_PCIEXPRESS_MRIOV_X8"
            | "AGT_MODULE_ONEPORT_PCIEXPRESS_MRIOV_X16"
    ) {
        eprintln!("Error: Unsupported module type: {}", header.module_type);
        return;
    }

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
            .write_all(&0x0a0d0d0a_u32.to_le_bytes())
            .unwrap();

        let mut sh_data: Vec<u8> = Vec::new();
        sh_data.write_all(&0x1a2b3c4d_u32.to_le_bytes()).unwrap();
        sh_data.write_all(&0x0001_u16.to_le_bytes()).unwrap();
        sh_data.write_all(&0x0000_u16.to_le_bytes()).unwrap();
        sh_data.write_all(&(-1_i64).to_le_bytes()).unwrap();

        let sh_len: u32 = <usize as TryInto<u32>>::try_into(sh_data.len()).unwrap() + 4 * 3;
        pcapng_writer.write_all(&sh_len.to_le_bytes()).unwrap();
        pcapng_writer.write_all(&sh_data).unwrap();
        pcapng_writer.write_all(&sh_len.to_le_bytes()).unwrap();
    }

    // Interface Description Block
    {
        pcapng_writer
            .write_all(&0x00000001_u32.to_le_bytes())
            .unwrap();

        let mut if_data: Vec<u8> = Vec::new();
        if_data.write_all(&(147 + 11_u16).to_le_bytes()).unwrap();
        if_data.write_all(&0x0000_u16.to_le_bytes()).unwrap();
        if_data.write_all(&0_u32.to_le_bytes()).unwrap();

        // Options
        let if_name = header.port_id.clone().into_bytes();
        if_data.write_all(&2_u16.to_le_bytes()).unwrap();
        if_data
            .write_all(
                &<usize as TryInto<u16>>::try_into(if_name.len())
                    .unwrap()
                    .to_le_bytes(),
            )
            .unwrap();
        if_data.write_all(&if_name).unwrap();
        let padding_count = if if_data.len() % 4 != 0 {
            4 - (if_data.len() % 4)
        } else {
            0
        };
        if_data.resize(if_data.len() + padding_count, 0);

        /*
        if_data.append(&mut (8 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (8 as u16).to_le_bytes().to_vec());
        if_data.append(&mut (2e9 as u64).to_le_bytes().to_vec());
        */

        if_data.write_all(&9_u16.to_le_bytes()).unwrap();
        if_data.write_all(&1_u16.to_le_bytes()).unwrap();
        if_data.write_all(&9_u32.to_le_bytes()).unwrap();

        let if_hardware = header.module_type.clone().into_bytes();
        if_data.write_all(&15_u16.to_le_bytes()).unwrap();
        if_data
            .write_all(
                &<usize as TryInto<u16>>::try_into(if_hardware.len())
                    .unwrap()
                    .to_le_bytes(),
            )
            .unwrap();
        if_data.write_all(&if_hardware).unwrap();
        let padding_count = if if_data.len() % 4 != 0 {
            4 - (if_data.len() % 4)
        } else {
            0
        };
        if_data.resize(if_data.len() + padding_count, 0);

        if_data.write_all(&0_u16.to_le_bytes()).unwrap();
        if_data.write_all(&0_u16.to_le_bytes()).unwrap();

        let if_len: u32 = <usize as TryInto<u32>>::try_into(if_data.len()).unwrap() + 4 * 3;
        pcapng_writer.write_all(&if_len.to_le_bytes()).unwrap();
        pcapng_writer.write_all(&if_data).unwrap();
        pcapng_writer.write_all(&if_len.to_le_bytes()).unwrap();
    }

    for record in pad_file.records {
        assert_eq!(record.count, 1, "record \"count\" field is not equal to 1");

        let record_data = pad_file.record_reader.get_all_data_for_record(&record);

        // Enhanced Packet Block
        {
            pcapng_writer
                .write_all(&0x00000006_u32.to_le_bytes())
                .unwrap();

            let mut block_data: Vec<u8> = Vec::with_capacity(4 * 1024);
            block_data.write_all(&0_u32.to_le_bytes()).unwrap();
            block_data
                .write_all(
                    &<u64 as TryInto<u32>>::try_into(record.timestamp_ns.checked_shr(32).unwrap())
                        .unwrap()
                        .to_le_bytes(),
                )
                .unwrap();
            block_data
                .write_all(
                    &<u64 as TryInto<u32>>::try_into(record.timestamp_ns & ((1 << 32) - 1))
                        .unwrap()
                        .to_le_bytes(),
                )
                .unwrap();
            let record_data_len =
                4 + 8 + 2 + 2 + 4 + <usize as TryInto<u32>>::try_into(record_data.len()).unwrap();
            block_data
                .write_all(&record_data_len.to_le_bytes())
                .unwrap();
            block_data
                .write_all(&record_data_len.to_le_bytes())
                .unwrap();

            // Record metadata
            block_data.write_all(&record.number.to_le_bytes()).unwrap();
            block_data
                .write_all(&record.timestamp_ns.to_le_bytes())
                .unwrap();
            block_data.write_all(&record.lfsr.to_le_bytes()).unwrap();
            let value: u16 = if record.extra_metadata_present {
                0x8000
            } else {
                0
            } | record.metadata_offset;
            block_data.write_all(&value.to_le_bytes()).unwrap();
            block_data.write_all(&record.flags.to_le_bytes()).unwrap();

            // Record data
            block_data.write_all(&record_data).unwrap();
            let padding_count = if block_data.len() % 4 != 0 {
                4 - (block_data.len() % 4)
            } else {
                0
            };
            block_data.resize(block_data.len() + padding_count, 0);

            if (record.number == header.trigger_record_number)
                || (record.number == header.first_record_number
                    && header.trigger_record_number < header.first_record_number)
                || (record.number == header.last_record_number
                    && header.trigger_record_number > header.last_record_number)
            {
                let packet_comment = match header.timestamps_ns.trigger.cmp(&record.timestamp_ns) {
                    Ordering::Less => {
                        let difference_ns = record.timestamp_ns - header.timestamps_ns.trigger;
                        let ts_ns_int = difference_ns / 1000000000;
                        let ts_ns_frac = difference_ns % 1000000000;
                        format!(
                            "Triggered {}.{:09}s before this record.",
                            ts_ns_int, ts_ns_frac
                        )
                    }
                    Ordering::Equal => "Triggered on this record.".to_string(),
                    Ordering::Greater => {
                        let difference_ns = header.timestamps_ns.trigger - record.timestamp_ns;
                        let ts_ns_int = difference_ns / 1000000000;
                        let ts_ns_frac = difference_ns % 1000000000;
                        format!(
                            "Triggered {}.{:09}s after this record.",
                            ts_ns_int, ts_ns_frac
                        )
                    }
                }
                .into_bytes();
                block_data.write_all(&1_u16.to_le_bytes()).unwrap();
                block_data
                    .write_all(
                        &<usize as TryInto<u16>>::try_into(packet_comment.len())
                            .unwrap()
                            .to_le_bytes(),
                    )
                    .unwrap();
                block_data.write_all(&packet_comment).unwrap();
                let padding_count = if block_data.len() % 4 != 0 {
                    4 - (block_data.len() % 4)
                } else {
                    0
                };
                block_data.resize(block_data.len() + padding_count, 0);

                block_data.write_all(&0_u16.to_le_bytes()).unwrap();
                block_data.write_all(&0_u16.to_le_bytes()).unwrap();
            }

            let block_len: u32 =
                <usize as TryInto<u32>>::try_into(block_data.len()).unwrap() + 4 * 3;
            pcapng_writer.write_all(&block_len.to_le_bytes()).unwrap();
            pcapng_writer.write_all(&block_data).unwrap();
            pcapng_writer.write_all(&block_len.to_le_bytes()).unwrap();
        }
    }
}
