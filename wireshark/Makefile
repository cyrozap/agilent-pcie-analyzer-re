# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright (C) 2023-2024  Forest Crossman <cyrozap@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


CFLAGS := $(shell pkg-config --cflags wireshark) -std=c17 -fPIC -Wall -Werror -O2
LDFLAGS := $(shell pkg-config --libs wireshark)

PLUGINS_VERSION = 4.4
PLUGINS_DIRECTORY = $(HOME)/.local/lib/wireshark/plugins/$(PLUGINS_VERSION)/epan
PLUGIN_WANT_MAJOR = $(word 1,$(subst ., ,$(PLUGINS_VERSION)))
PLUGIN_WANT_MINOR = $(word 2,$(subst ., ,$(PLUGINS_VERSION)))


all: pcie.so

%.o: %.c
	$(CC) $(CFLAGS) -D PLUGIN_WANT_MAJOR=$(PLUGIN_WANT_MAJOR) -D PLUGIN_WANT_MINOR=$(PLUGIN_WANT_MINOR) -c -o $@ $<

pcie.so: plugin.o proto_pcie.o proto_nettlp.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^

install: pcie.so
	install -Dm755 $< $(PLUGINS_DIRECTORY)/$<

link: pcie.so
	install -dm755 $(PLUGINS_DIRECTORY)
	ln -s $(CURDIR)/$< $(PLUGINS_DIRECTORY)/$<

clean:
	rm -f *.o *.so


.PHONY: all clean install link
