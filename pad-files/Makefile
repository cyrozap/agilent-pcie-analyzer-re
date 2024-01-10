# SPDX-License-Identifier: 0BSD

# Copyright (C) 2024 by Forest Crossman <cyrozap@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
# PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.


PAD2PCAPNG ?= ../tools/agilent_pad/target/release/examples/pad2pcapng
ZSTD ?= zstd
ZSTD_FLAGS ?= -T0 -19

COMPRESSED_PAD_FILES := $(wildcard *.pad.zst)
DECOMPRESSED_PAD_FILES := $(COMPRESSED_PAD_FILES:%.pad.zst=%.pad)
OTHER_PAD_FILES := $(wildcard *.pad)

PAD_TARGETS := $(DECOMPRESSED_PAD_FILES) $(OTHER_PAD_FILES)
PCAPNG_TARGETS := $(PAD_TARGETS:%.pad=%.pcapng)
COMPRESSED_PCAPNG_TARGETS := $(PCAPNG_TARGETS:%.pcapng=%.pcapng.zst)


all: $(COMPRESSED_PCAPNG_TARGETS)

%.pcapng.zst: %.pcapng
	$(ZSTD) $(ZSTD_FLAGS) -o $@ $<

%.pcapng: %.pad $(PAD2PCAPNG)
	$(PAD2PCAPNG) $< $@

%.pad: %.pad.zst
	$(ZSTD) -d -o $@ $<

../tools/agilent_pad/target/release/examples/pad2pcapng:
	(cd ../tools/agilent_pad/ && cargo build --release --example pad2pcapng)

clean:
	rm -f $(COMPRESSED_PCAPNG_TARGETS) $(PCAPNG_TARGETS) $(DECOMPRESSED_PAD_FILES)


.PHONY: all clean
