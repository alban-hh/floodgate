CLANG ?= clang-12
LLC ?= llc-12
CC ?= gcc

KERNEL_SRC = src/floodgate_kern.c
USER_SRC = src/floodgate_user.c
KERNEL_OBJ = floodgate_kern.o
USER_BIN = floodgate

CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -O2 -g -I/usr/include -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf -lelf

all: $(KERNEL_OBJ) $(USER_BIN)

$(KERNEL_OBJ): $(KERNEL_SRC)
	$(CLANG) $(BPF_CFLAGS) -D__BPF_TRACING__ -D__KERNEL__ \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-target bpf -c $< -o $@

$(USER_BIN): $(USER_SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(KERNEL_OBJ) $(USER_BIN)

install: all
	install -m 0755 $(USER_BIN) /usr/local/bin/
	install -m 0644 $(KERNEL_OBJ) /usr/local/lib/

load: all
	./$(USER_BIN) -i eth0

.PHONY: all clean install load
