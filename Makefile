# ==================== 构建配置 ====================
CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CC ?= gcc

# 构建类型配置
BUILD_TYPE ?= release
DEBUG_LEVEL ?= 0

# 根据构建类型设置编译标志
ifeq ($(BUILD_TYPE),debug)
    # Debug版本配置
    CFLAGS += -g -O0 -DDEBUG -DDEBUG_LEVEL=$(DEBUG_LEVEL) -Wall -Wextra -Wpedantic
    CFLAGS += -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
    CFLAGS += -DTRACE_ENABLED -DASSERT_ENABLED
    LDFLAGS += -fsanitize=address -fsanitize=undefined
    BPF_CFLAGS += -g -O0 -DDEBUG
    BUILD_SUFFIX = _debug
    DEBUG_INFO = 1
else ifeq ($(BUILD_TYPE),release)
    # Release版本配置
    CFLAGS += -O3 -DNDEBUG -march=native -mtune=native
    CFLAGS += -flto -ffast-math -funroll-loops
    CFLAGS += -fomit-frame-pointer -DRELEASE_BUILD
    LDFLAGS += -flto
    BPF_CFLAGS += -O2 -DNDEBUG
    BUILD_SUFFIX = _release
    DEBUG_INFO = 0
else ifeq ($(BUILD_TYPE),profile)
    # Profile版本配置（用于性能分析）
    CFLAGS += -O2 -g -pg -DDEBUG_LEVEL=1
    CFLAGS += -fno-omit-frame-pointer -DTRACE_ENABLED
    LDFLAGS += -pg
    BPF_CFLAGS += -O2 -g
    BUILD_SUFFIX = _profile
    DEBUG_INFO = 1
else
    # 默认release配置
    BUILD_TYPE = release
    CFLAGS += -O3 -DNDEBUG -march=native
    BPF_CFLAGS += -O2 -DNDEBUG
    BUILD_SUFFIX = _release
    DEBUG_INFO = 0
endif

# libbpf directories - 使用本地include目录
LIBBPF_SRC := $(abspath include)

# 通用编译标志
CFLAGS += -std=c11 -Wall -I$(LIBBPF_SRC)
CFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L

# BPF编译器标志
BPF_CFLAGS += -target bpf -D__TARGET_ARCH_$(ARCH) \
             -I. \
             -I$(LIBBPF_SRC) \
             -I/usr/include \
             -I/usr/include/linux \
             -I/usr/include/$(shell uname -m)-linux-gnu \
             -Werror -Wno-unused-value -Wno-pointer-sign \
             -g -O2 -mcpu=v3

# 库链接标志
LDLIBS := -lelf -lz -lbpf -lm -lpcap
JSON_LDLIBS := $(LDLIBS) -lcjson

# 确定正确的库路径
LIB64_DIR := /usr/lib64
LIB_DIR := /usr/lib

# 构建信息
BUILD_INFO := $(shell date +"%Y-%m-%d %H:%M:%S")
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION := 1.0.0

# 编译时定义
CFLAGS += -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\"

# ==================== 目标文件 ====================
TARGETS := loader
DEBUG_TARGETS := $(addsuffix $(BUILD_SUFFIX),$(TARGETS))
RELEASE_TARGETS := $(addsuffix _release,$(TARGETS))
PROFILE_TARGETS := $(addsuffix _profile,$(TARGETS))

# 主目标 - 包含BPF程序
all: bpf_program.o $(TARGETS)

# Debug版本
debug: CFLAGS += -g -O0 -DDEBUG -DDEBUG_LEVEL=$(DEBUG_LEVEL) -Wall -Wextra -Wpedantic
debug: CFLAGS += -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: loader_debug

# Release版本
release: CFLAGS += -O3 -DNDEBUG -march=native -mtune=native
release: CFLAGS += -flto -ffast-math -funroll-loops -fomit-frame-pointer
release: LDFLAGS += -flto
release: loader_release

# Profile版本
profile: CFLAGS += -O2 -g -pg -DDEBUG_LEVEL=1
profile: CFLAGS += -fno-omit-frame-pointer -DTRACE_ENABLED
profile: LDFLAGS += -pg
profile: loader_profile

# 所有版本
all-versions: debug release profile

# ==================== BPF程序编译 ====================
bpf_program.o: bpf_program.c
	@echo "编译BPF程序 ($(BUILD_TYPE)版本)..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ==================== 应用程序编译 ====================

# Loader应用程序
loader: loader.c flow.c mempool.c transport_session.c
	@echo "编译loader ($(BUILD_TYPE)版本)..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

loader_debug: loader.c flow.c mempool.c transport_session.c
	@echo "编译loader (debug版本)..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

loader_release: loader.c flow.c mempool.c transport_session.c
	@echo "编译loader (release版本)..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

loader_profile: loader.c flow.c mempool.c transport_session.c
	@echo "编译loader (profile版本)..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

loader_debug_noasan: loader.c flow.c mempool.c transport_session.c
	@echo "编译loader (debug版本，无ASan，用于Valgrind)..."
	$(CC) $(CFLAGS) -g -O0 -DDEBUG -DDEBUG_LEVEL=$(DEBUG_LEVEL) -Wall -Wextra -Wpedantic \
		-fno-omit-frame-pointer -DTRACE_ENABLED -DASSERT_ENABLED \
		$(LDFLAGS) -o $@ $^ $(LDLIBS)

# 其他应用程序可以根据需要添加

# ==================== 运行时路径修复 ====================
fix_rpath:
	@if [ -f loader ]; then \
		echo "添加运行时库搜索路径到可执行文件..."; \
		if [ -d $(LIB64_DIR) ]; then \
			patchelf --set-rpath $(LIB64_DIR) loader; \
		else \
			patchelf --set-rpath $(LIB_DIR) loader; \
		fi; \
	fi
	@if [ -f filter_manager ]; then \
		echo "添加运行时库搜索路径到过滤器管理程序..."; \
		if [ -d $(LIB64_DIR) ]; then \
			patchelf --set-rpath $(LIB64_DIR) filter_manager; \
		else \
			patchelf --set-rpath $(LIB_DIR) filter_manager; \
		fi; \
	fi
	@if [ -f filter_json_manager ]; then \
		echo "添加运行时库搜索路径到JSON过滤器管理程序..."; \
		if [ -d $(LIB64_DIR) ]; then \
			patchelf --set-rpath $(LIB64_DIR) filter_json_manager; \
		else \
			patchelf --set-rpath $(LIB_DIR) filter_json_manager; \
		fi; \
	fi

# ==================== 权限检查 ====================
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

# ==================== 安装目标 ====================
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
	sudo install -m 755 filter_manager /usr/bin/ebpf_filter
	sudo install -m 755 filter_json_manager /usr/bin/ebpf_filter_json
	sudo mkdir -p /usr/share/ebpf_pkt
	sudo install -m 644 bpf_program.o /usr/share/ebpf_pkt/
	@echo "安装完成! 可以使用 'ebpf_pkt' 命令运行程序"
	@echo "可以使用 'ebpf_filter' 命令管理过滤规则"
	@echo "可以使用 'ebpf_filter_json' 命令管理 JSON 过滤规则"
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

# ==================== 性能分析工具 ====================
install-perf-tools:
	@echo "安装性能分析工具..."
	sudo apt-get update
	sudo apt-get install -y perf-tools-unstable valgrind gprof
	@echo "性能分析工具安装完成"

# 使用gprof进行性能分析
profile-gprof: profile
	@echo "运行gprof性能分析..."
	./loader_profile -i lo -c 1000
	gprof loader_profile gmon.out > profile_report.txt
	@echo "性能分析报告已保存到 profile_report.txt"

# 使用perf进行性能分析
profile-perf: release
	@echo "运行perf性能分析..."
	sudo perf record -g ./loader_release -i lo -c 1000
	sudo perf report --stdio > perf_report.txt
	@echo "perf分析报告已保存到 perf_report.txt"

# 使用valgrind进行内存检查
memcheck: debug-noasan
	@echo "运行valgrind内存检查..."
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
		--track-origins=yes --verbose --log-file=valgrind_report.txt \
		./loader_debug_noasan -i lo -c 100
	@echo "内存检查报告已保存到 valgrind_report.txt"

# Debug版本（无ASan，用于Valgrind）
debug-noasan: CFLAGS += -g -O0 -DDEBUG -DDEBUG_LEVEL=$(DEBUG_LEVEL) -Wall -Wextra -Wpedantic
debug-noasan: CFLAGS += -fno-omit-frame-pointer
debug-noasan: CFLAGS += -DTRACE_ENABLED -DASSERT_ENABLED
debug-noasan: BPF_CFLAGS += -g -O0 -DDEBUG
debug-noasan: loader_debug_noasan

# ==================== 清理目标 ====================
clean:
	rm -f *.o loader filter_manager filter_json_manager test_* ebpf_pkt.sh
	rm -f loader_debug loader_release loader_profile loader_debug_noasan
	rm -f gmon.out profile_report.txt perf_report.txt valgrind_report.txt
	rm -f *.debug *.release *.profile

clean-all: clean
	rm -f *.csv *.txt *.log
	rm -rf debug/ release/ profile/

# ==================== 帮助信息 ====================
help:
	@echo "可用的构建目标:"
	@echo "  all              - 构建默认版本 ($(BUILD_TYPE))"
	@echo "  debug            - 构建debug版本 (包含调试信息和sanitizer)"
	@echo "  release          - 构建release版本 (优化性能)"
	@echo "  profile          - 构建profile版本 (用于性能分析)"
	@echo "  all-versions     - 构建所有版本"
	@echo ""
	@echo "性能分析:"
	@echo "  profile-gprof    - 使用gprof进行性能分析"
	@echo "  profile-perf     - 使用perf进行性能分析"
	@echo "  memcheck         - 使用valgrind进行内存检查"
	@echo ""
	@echo "安装和维护:"
	@echo "  install_all      - 完整安装"
	@echo "  install-perf-tools - 安装性能分析工具"
	@echo "  clean            - 清理构建文件"
	@echo "  clean-all        - 清理所有文件"
	@echo ""
	@echo "环境变量:"
	@echo "  BUILD_TYPE       - 构建类型 (debug/release/profile, 默认: $(BUILD_TYPE))"
	@echo "  DEBUG_LEVEL      - 调试级别 (0-3, 默认: $(DEBUG_LEVEL))"
	@echo ""
	@echo "示例:"
	@echo "  make debug DEBUG_LEVEL=3"
	@echo "  make release"
	@echo "  make profile-gprof"

# ==================== 创建启动脚本 ====================
wrapper:
	@echo "#!/bin/bash" > ebpf_pkt.sh
	@echo "export LD_LIBRARY_PATH=\$$LD_LIBRARY_PATH:/usr/lib64:/usr/lib" >> ebpf_pkt.sh
	@echo "./loader \$$@" >> ebpf_pkt.sh
	@chmod +x ebpf_pkt.sh
	@echo "创建了启动脚本 ebpf_pkt.sh - 使用这个来运行程序"

.PHONY: all debug release profile all-versions clean clean-all help wrapper install_all fix_rpath check_privileges install-perf-tools profile-gprof profile-perf memcheck