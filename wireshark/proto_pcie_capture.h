// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_pcie_capture.h - PCIe capture dissector for Wireshark.
 *  Copyright (C) 2025  Forest Crossman <cyrozap@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
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

#ifndef PROTO_PCIE_CAPTURE_H_INCLUDED
#define PROTO_PCIE_CAPTURE_H_INCLUDED

void proto_register_pcie_capture();
void proto_reg_handoff_pcie_capture();

#endif // PROTO_PCIE_CAPTURE_H_INCLUDED
