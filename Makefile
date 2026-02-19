CLANG ?= clang-12
LLC ?= llc-12
CC ?= gcc

KERN_SRC = src/kern/floodgate_kern.c
KERN_OBJ = floodgate_kern.o
USER_BIN = floodgate

USER_SRCS = src/user/main.c \
            src/user/globals.c \
            src/user/config.c \
            src/user/stats.c \
            src/user/sflow.c \
            src/user/acl.c \
            src/user/flowspec.c

USER_OBJS = $(patsubst src/user/%.c,build/%.o,$(USER_SRCS))

CFLAGS = -O2 -g -Wall -I include
BPF_CFLAGS = -O2 -g -I include -I /usr/include -I /usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf -lelf -lpthread

all: $(KERN_OBJ) $(USER_BIN)

$(KERN_OBJ): $(KERN_SRC) include/floodgate_common.h
	$(CLANG) $(BPF_CFLAGS) -D__BPF_TRACING__ -D__KERNEL__ \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-target bpf -c $< -o $@

build/%.o: src/user/%.c include/floodgate_common.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf build $(KERN_OBJ) $(USER_BIN)

install: all
	install -m 0755 $(USER_BIN) /usr/local/bin/
	install -m 0644 $(KERN_OBJ) /usr/local/lib/
	mkdir -p /etc/floodgate
	test -f /etc/floodgate/whitelist.txt || install -m 0644 config/whitelist.txt /etc/floodgate/
	install -m 0644 config/floodgate.service /etc/systemd/system/
	install -m 0644 config/99-floodgate-sysctl.conf /etc/sysctl.d/99-floodgate.conf
	sysctl --system 2>/dev/null || true
	systemctl daemon-reload

uninstall:
	rm -f /usr/local/bin/$(USER_BIN)
	rm -f /usr/local/lib/$(KERN_OBJ)
	rm -f /etc/systemd/system/floodgate.service
	systemctl daemon-reload

.PHONY: all clean install uninstall
