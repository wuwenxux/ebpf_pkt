# 编译配置
CC = cc
CLANG = clang

# 本地libbpf路径
LOCAL_LIBBPF_PATH = /root/Projects/ebpf_pkt/usr
LOCAL_LIBBPF_INCLUDE = $(LOCAL_LIBBPF_PATH)/include
LOCAL_LIBBPF_LIB = $(LOCAL_LIBBPF_PATH)/lib64

# 构建类型和日志级别
BUILD_TYPE ?= release
LOG_LEVEL ?= 1

# 根据构建类型设置编译标志
ifeq ($(BUILD_TYPE),debug)
    CFLAGS = -std=c11 -Wall -I$(LOCAL_LIBBPF_INCLUDE) -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -g -DDEBUG -O0 -DLOG_LEVEL=2
    BPF_CFLAGS = -g -DDEBUG -O0 -target bpf -D__TARGET_ARCH_x86 -I. -I$(LOCAL_LIBBPF_INCLUDE) -I/usr/include -I/usr/include/linux -I/usr/include/x86_64-linux-gnu -Werror -Wno-unused-value -Wno-pointer-sign -mcpu=v3 -g
    OPTIMIZATION_FLAGS = -g -DDEBUG -O0
    LOG_LEVEL = 2
else ifeq ($(BUILD_TYPE),profile)
    CFLAGS = -std=c11 -Wall -I$(LOCAL_LIBBPF_INCLUDE) -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -g -pg -O2 -DLOG_LEVEL=1
    BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -I$(LOCAL_LIBBPF_INCLUDE) -I/usr/include -I/usr/include/linux -I/usr/include/x86_64-linux-gnu -Werror -Wno-unused-value -Wno-pointer-sign -mcpu=v3 -g
    OPTIMIZATION_FLAGS = -g -pg -O2
    LOG_LEVEL = 1
else
    # release版本
    CFLAGS = -std=c11 -Wall -I$(LOCAL_LIBBPF_INCLUDE) -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -O3 -DNDEBUG -DLOG_LEVEL=0
    BPF_CFLAGS = -O2 -DNDEBUG -target bpf -D__TARGET_ARCH_x86 -I. -I$(LOCAL_LIBBPF_INCLUDE) -I/usr/include -I/usr/include/linux -I/usr/include/x86_64-linux-gnu -Werror -Wno-unused-value -Wno-pointer-sign -mcpu=v3 -g
    OPTIMIZATION_FLAGS = -O3 -DNDEBUG -march=native -mtune=native -flto -ffast-math -funroll-loops -fomit-frame-pointer -fno-sanitize=address -fno-sanitize=undefined
    LOG_LEVEL = 0
endif

# 构建信息
GIT_HASH = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION = 1.0.0

# 源文件
LOADER_SOURCES = loader_core.c lockfree_queue.c worker_threads.c ringbuf_handler.c interface_manager.c
FLOW_SOURCES = flow.c mempool.c
TRANSPORT_SOURCES = transport_session.c
LOGGER_SOURCES = logger.c
STATS_SOURCES = stats_window.c system_stats.c

# 目标文件
LOADER_OBJECTS = $(LOADER_SOURCES:.c=.o)
FLOW_OBJECTS = $(FLOW_SOURCES:.c=.o)
TRANSPORT_OBJECTS = $(TRANSPORT_SOURCES:.c=.o)
LOGGER_OBJECTS = $(LOGGER_SOURCES:.c=.o)
STATS_OBJECTS = $(STATS_SOURCES:.c=.o)

# 库文件 - 使用本地libbpf
LIBS = -lelf -lz -lm -lpcap -lncurses
LDFLAGS = -L$(LOCAL_LIBBPF_LIB) -lbpf

# 运行时库路径
RPATH = -Wl,-rpath,$(LOCAL_LIBBPF_LIB)

# 默认目标
all: release

# 编译BPF程序
bpf_program.o: bpf_program.c
	@echo "编译BPF程序 ($(BUILD_TYPE)版本)..."
	$(CLANG) $(BPF_CFLAGS) -c bpf_program.c -o bpf_program.o

# 编译核心模块
loader_core.o: loader_core.c
	@echo "编译loader_core.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c loader_core.c -o loader_core.o

# 编译无锁队列模块
lockfree_queue.o: lockfree_queue.c
	@echo "编译lockfree_queue.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c lockfree_queue.c -o lockfree_queue.o

# 编译工作线程模块
worker_threads.o: worker_threads.c
	@echo "编译worker_threads.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c worker_threads.c -o worker_threads.o

# 编译RINGBUF处理模块
ringbuf_handler.o: ringbuf_handler.c
	@echo "编译ringbuf_handler.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c ringbuf_handler.c -o ringbuf_handler.o

# 编译接口管理模块
interface_manager.o: interface_manager.c
	@echo "编译interface_manager.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c interface_manager.c -o interface_manager.o

# 编译流处理模块
flow.o: flow.c
	@echo "编译flow.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c flow.c -o flow.o

# 编译内存池模块
mempool.o: mempool.c
	@echo "编译mempool.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c mempool.c -o mempool.o

# 编译传输会话模块
transport_session.o: transport_session.c
	@echo "编译transport_session.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c transport_session.c -o transport_session.o

# 编译日志模块
logger.o: logger.c
	@echo "编译logger.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c logger.c -o logger.o

# 编译统计窗口模块
stats_window.o: stats_window.c
	@echo "编译stats_window.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c stats_window.c -o stats_window.o

# 编译系统统计模块
system_stats.o: system_stats.c
	@echo "编译system_stats.o..."
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -c system_stats.c -o system_stats.o

# 编译主程序
loader: bpf_program.o $(LOADER_OBJECTS) $(FLOW_OBJECTS) $(TRANSPORT_OBJECTS) $(LOGGER_OBJECTS) $(STATS_OBJECTS)
	@echo "编译loader_$(BUILD_TYPE) ($(BUILD_TYPE)版本)..."
	@echo "构建类型: $(BUILD_TYPE)"
	@echo "日志级别: $(LOG_LEVEL)"
	@echo "使用本地libbpf库: $(LOCAL_LIBBPF_LIB)"
	@echo "Git哈希: $(GIT_HASH)"
	@echo "版本: $(VERSION)"
	$(CC) $(CFLAGS) $(OPTIMIZATION_FLAGS) -DBUILD_TYPE=\"$(BUILD_TYPE)\" -DGIT_HASH=\"$(GIT_HASH)\" -DVERSION=\"$(VERSION)\" -flto $(RPATH) -o loader_$(BUILD_TYPE) $(LOADER_OBJECTS) $(FLOW_OBJECTS) $(TRANSPORT_OBJECTS) $(LOGGER_OBJECTS) $(STATS_OBJECTS) $(LDFLAGS) $(LIBS)

# 构建目标
debug: BUILD_TYPE=debug
debug: loader_debug

release: BUILD_TYPE=release
release: loader_release

profile: BUILD_TYPE=profile
profile: loader_profile

# 为不同构建类型创建符号链接
loader_debug: BUILD_TYPE=debug
loader_debug: loader

loader_release: BUILD_TYPE=release
loader_release: loader

loader_profile: BUILD_TYPE=profile
loader_profile: loader

# 清理
clean:
	rm -f *.o loader filter_manager filter_json_manager test_* ebpf_pkt.sh
	rm -f loader_debug loader_release loader_profile loader_debug_noasan
	rm -f gmon.out profile_report.txt perf_report.txt valgrind_report.txt
	rm -f *.debug *.release *.profile

# 安装
install: loader_release
	install -m 755 loader_release /usr/local/bin/loader
	install -m 644 bpf_program.o /usr/local/lib/

# 卸载
uninstall:
	rm -f /usr/local/bin/loader
	rm -f /usr/local/lib/bpf_program.o

# 测试
test: loader_release
	@echo "运行测试..."
	@echo "检查libbpf库路径..."
	@ldd ./loader_release | grep libbpf || echo "libbpf库未找到，请检查路径"
	./loader_release -h

# 检查libbpf版本
check-libbpf:
	@echo "检查本地libbpf库..."
	@echo "库路径: $(LOCAL_LIBBPF_LIB)"
	@ls -la $(LOCAL_LIBBPF_LIB)/libbpf*
	@echo ""
	@echo "头文件路径: $(LOCAL_LIBBPF_INCLUDE)"
	@ls -la $(LOCAL_LIBBPF_INCLUDE)/bpf/ 2>/dev/null || echo "头文件目录不存在"
	@echo ""
	@echo "pkg-config信息:"
	@PKG_CONFIG_PATH=$(LOCAL_LIBBPF_LIB)/pkgconfig pkg-config --modversion libbpf 2>/dev/null || echo "pkg-config信息不可用"

# 显示构建配置
config:
	@echo "=== 构建配置 ==="
	@echo "构建类型: $(BUILD_TYPE)"
	@echo "日志级别: $(LOG_LEVEL)"
	@echo "编译器: $(CC)"
	@echo "CLANG: $(CLANG)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "BPF_CFLAGS: $(BPF_CFLAGS)"
	@echo "OPTIMIZATION_FLAGS: $(OPTIMIZATION_FLAGS)"
	@echo "libbpf路径: $(LOCAL_LIBBPF_LIB)"
	@echo "libbpf头文件: $(LOCAL_LIBBPF_INCLUDE)"
	@echo "Git哈希: $(GIT_HASH)"
	@echo "版本: $(VERSION)"
	@echo "================"

# 帮助
help:
	@echo "=== eBPF Packet Monitor 构建系统 ==="
	@echo ""
	@echo "构建目标:"
	@echo "  all         - 编译release版本 (默认)"
	@echo "  release     - 编译loader_release (优化性能，日志级别0)"
	@echo "  debug       - 编译loader_debug (调试信息，日志级别2)"
	@echo "  profile     - 编译loader_profile (性能分析，日志级别1)"
	@echo ""
	@echo "日志级别说明:"
	@echo "  0 (ERROR)   - 只显示错误信息 (release版本)"
	@echo "  1 (WARN)    - 显示警告和错误 (profile版本)"
	@echo "  2 (INFO)    - 显示信息、警告和错误 (debug版本)"
	@echo ""
	@echo "其他目标:"
	@echo "  clean       - 清理编译文件"
	@echo "  install     - 安装到系统"
	@echo "  uninstall   - 从系统卸载"
	@echo "  test        - 运行基本测试"
	@echo "  check-libbpf- 检查libbpf库信息"
	@echo "  config      - 显示当前构建配置"
	@echo "  help        - 显示此帮助"
	@echo ""
	@echo "使用示例:"
	@echo "  make debug    # 编译loader_debug"
	@echo "  make release  # 编译loader_release"
	@echo "  make profile  # 编译loader_profile"
	@echo "  ./loader_debug -i enp1s0    # 运行debug版本"
	@echo "  ./loader_release -i enp1s0  # 运行release版本"
	@echo ""
	@echo "使用的libbpf库路径: $(LOCAL_LIBBPF_LIB)"

.PHONY: all release debug profile clean install uninstall test check-libbpf config help