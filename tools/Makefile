TARGETS=agilent_pad.py

all: $(TARGETS)

%.py: %.ksy
	kaitai-struct-compiler -t python $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
