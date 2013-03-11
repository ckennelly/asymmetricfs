BASERW   := $(shell mktemp -d)
TARGETRW := $(shell mktemp -d)
BASEWO   := $(shell mktemp -d)
TARGETWO := $(shell mktemp -d)

ROOT :=$(abspath .)

all: rw wo

rw:
	mkdir -p "$(BASERW)"
	../asymmetricfs -r 0x74353699 --rw "$(BASERW)" "$(TARGETRW)"
	cd "$(TARGETRW)"; BASE="${BASERW}" MODE="rw" find $(ROOT) -maxdepth 1 -type f -name '*.sh' -perm /u=x -exec {} \;
	fusermount -u "$(TARGETRW)"
	rm -rf "$(BASERW)"

wo:
	mkdir -p "$(BASEWO)"
	../asymmetricfs -r 0x74353699 --wo "$(BASEWO)" "$(TARGETWO)"
	cd "$(TARGETWO)"; BASE="${BASEWO}" MODE="wo" find $(ROOT) -maxdepth 1 -type f -name '*.sh' -perm /u=x -exec {} \;
	fusermount -u "$(TARGETWO)"
	rm -rf "$(BASEWO)"
