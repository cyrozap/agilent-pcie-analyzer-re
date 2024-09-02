// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  plugin.c - PCIe dissector plugin for Wireshark.
 *  Copyright (C) 2023-2024  Forest Crossman <cyrozap@gmail.com>
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

#include <stdint.h>

#include <epan/proto.h>

#include "proto_nettlp.h"
#include "proto_pcie.h"


char const plugin_version[] = "0.1.0";
uint32_t const plugin_want_major = PLUGIN_WANT_MAJOR;
uint32_t const plugin_want_minor = PLUGIN_WANT_MINOR;


static void proto_register_all(void) {
    proto_register_pcie();
    proto_register_nettlp();
}

static void proto_reg_handoff_all(void) {
    proto_reg_handoff_pcie();
    proto_reg_handoff_nettlp();
}

static const proto_plugin plugin_pcie = {
    .register_protoinfo = proto_register_all,
    .register_handoff = proto_reg_handoff_all,
};

void plugin_register(void) {
    proto_register_plugin(&plugin_pcie);
}
