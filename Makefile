CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
LIBBPF_VER := $(shell pkg-config --modversion libbpf | cut -d. -f1)
CFLAGS += -DLIBBPF_MAJOR_VERSION=$(LIBBPF_VER)

BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
             -I. -I/usr/include \
			 -I/usr/include/linux \
             -I/usr/include/$(shell uname -m)-linux-gnu \
             -Werror -Wno-unused-value -Wno-pointer-sign
LDLIBS := -lelf -lz -lbpf -lm -lpcap

all: bpf_program.o loader

bpf_program.o: bpf_program.c 
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c flow.c mempool.c 
	$(CC) -g -O2 -Wall -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o loader

.PHONY: all clean