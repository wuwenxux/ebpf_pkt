CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CC ?= gcc

# libbpf directories
LIBBPF_SRC := $(abspath libbpf/src)

# BPF compiler flags
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
             -I. \
             -I$(LIBBPF_SRC) \
             -I/usr/include \
             -I/usr/include/linux \
             -I/usr/include/$(shell uname -m)-linux-gnu \
             -Werror -Wno-unused-value -Wno-pointer-sign

# Application CFLAGS and LDFLAGS
CFLAGS += -g -O2 -Wall -I$(LIBBPF_SRC)
LDLIBS := -lelf -lz -lbpf -lm -lpcap

# 确定正确的库路径
LIB64_DIR := /usr/lib64
LIB_DIR := /usr/lib

# Main target
all: bpf_program.o loader

# BPF program compilation
bpf_program.o: bpf_program.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Loader application
loader: loader.c flow.c mempool.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# 添加运行时路径信息
fix_rpath:
	@if [ -f loader ]; then \
		echo "添加运行时库搜索路径到可执行文件..."; \
		if [ -d $(LIB64_DIR) ]; then \
			patchelf --set-rpath $(LIB64_DIR) loader; \
		else \
			patchelf --set-rpath $(LIB_DIR) loader; \
		fi; \
	fi

# 检查和启用特权模式
check_privileges:
	@echo "检查 eBPF 特权模式..."
	@if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ] && [ $$(cat /proc/sys/kernel/unprivileged_bpf_disabled) -eq 1 ]; then \
		echo "特权模式已启用 - 请确保使用 root 或 sudo 运行"; \
	else \
		echo "==================================================="; \
		echo "注意: 可能需要设置 eBPF 特权模式!"; \
		echo "如果运行时出现 'Operation not permitted' 错误，请运行:"; \
		echo "sudo sysctl -w kernel.unprivileged_bpf_disabled=1"; \
		echo "sudo sysctl -w kernel.bpf_stats_enabled=1"; \
		echo "sudo sysctl -w net.core.bpf_jit_enable=1"; \
		echo "==================================================="; \
	fi

# 一步完成编译和安装（需要 root 权限）
install_all: check_privileges
	@echo "=== 安装 libbpf 到系统 ==="
	sudo $(MAKE) -C $(LIBBPF_SRC) install PREFIX=/usr
	@echo "创建符号链接"
	@if [ -d $(LIB64_DIR) ]; then \
		if [ -f $(LIB64_DIR)/libbpf.so.1 ] && [ ! -L $(LIB_DIR)/libbpf.so.1 ]; then \
			sudo ln -sf $(LIB64_DIR)/libbpf.so.1 $(LIB_DIR)/libbpf.so.1; \
		elif [ -f $(LIB_DIR)/libbpf.so.1 ] && [ ! -L $(LIB64_DIR)/libbpf.so.1 ]; then \
			sudo ln -sf $(LIB_DIR)/libbpf.so.1 $(LIB64_DIR)/libbpf.so.1; \
		fi; \
	fi
	@echo "更新共享库缓存..."
	sudo ldconfig
	@echo ""
	
	@echo "=== 编译应用程序 ==="
	@$(MAKE) all
	@echo ""

	@echo "=== 添加运行时库路径 ==="
	@if command -v patchelf > /dev/null; then \
		$(MAKE) fix_rpath; \
	else \
		echo "警告: 没有安装 patchelf，无法添加 RPATH. 可能需要手动设置 LD_LIBRARY_PATH"; \
	fi
	@echo ""
	
	@echo "=== 安装应用程序 ==="
	sudo install -m 755 loader /usr/bin/ebpf_pkt
	sudo mkdir -p /usr/share/ebpf_pkt
	sudo install -m 644 bpf_program.o /usr/share/ebpf_pkt/
	@echo "安装完成! 可以使用 'ebpf_pkt' 命令运行程序"
	@echo ""
	@echo "如果仍然有库问题，请尝试运行:"
	@echo "export LD_LIBRARY_PATH=\$$LD_LIBRARY_PATH:/usr/lib64:/usr/lib"
	@echo ""
	@echo "=== eBPF 权限须知 ==="
	@echo "运行时如果出现 'Operation not permitted' 或 'Permission denied' 错误，"
	@echo "请确保已设置以下系统参数:"
	@echo "sudo sysctl -w kernel.unprivileged_bpf_disabled=1"
	@echo "sudo sysctl -w kernel.bpf_stats_enabled=1"
	@echo "sudo sysctl -w net.core.bpf_jit_enable=1"

# 创建一个简单的脚本来运行程序
wrapper:
	@echo "#!/bin/bash" > ebpf_pkt.sh
	@echo "export LD_LIBRARY_PATH=\$$LD_LIBRARY_PATH:/usr/lib64:/usr/lib" >> ebpf_pkt.sh
	@echo "./loader \$$@" >> ebpf_pkt.sh
	@chmod +x ebpf_pkt.sh
	@echo "创建了启动脚本 ebpf_pkt.sh - 使用这个来运行程序"

clean:
	rm -f *.o loader ebpf_pkt.sh

.PHONY: all clean install_all fix_rpath wrapper check_privileges