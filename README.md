# eBPF Packet

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 📖 简介

本项目是一个基于eBPF技术的高性能网络数据包捕获工具，能够在内核空间高效捕获和分析网络流量。通过eBPF的沙箱机制，实现低开销的网络监控，支持自定义过滤规则和流量统计。

## 🚀 主要功能

- ✅ 实时捕获IPv4/TCP/UDP协议流量
- ✅ 支持BPF过滤语法（类似tcpdump语法）未来实现
- ✅ 显示数据包元数据（时间戳、协议、源/目的地址、端口等）
- ✅ 流量统计（包计数、字节数统计）
- ✅ 低资源消耗（内核态处理+用户态聚合）
- ✅ 支持保存捕获结果到PCAP格式文件

## 🛠️ 环境要求

- **Linux内核版本** ≥ 4.18
- **LLVM** ≥ 10
- **Clang** ≥ 10
- **libbpf** 开发库
- **Python 3** (用于辅助脚本)

## 📦 安装步骤

```bash
# 安装依赖
sudo apt-get update && sudo apt-get install -y \
    clang llvm libelf-dev libbpf-dev \
    python3 python3-pip

# 编译eBPF程序
make

### 使用说明
   - `wwx0306@foxmail.com`
   - `https://github.com/wuwenxux/ebpf_pkt`
3. 支持的特性图标（✅）可以根据实际开发进度替换为其他状态符号

### 效果预览
在支持Markdown渲染的环境（如GitHub/GitLab）中会自动显示：
- 带格式的表格
- 语法高亮的代码块
- 可点击的徽章和链接
- 层级清晰的标题结构

# eBPF 网络流量监控工具

这个工具使用 eBPF 技术监控网络流量，统计流量数据并进行实时分析。

## 功能特点

- 使用 eBPF XDP 程序高效捕获数据包
- 支持实时网络接口监控和 pcap 文件分析
- 多线程处理以提高性能
- 支持 TCP/UDP 流量统计
- 流量按照流分组和统计
- 定期输出统计信息

## 系统要求

- Linux 内核 5.5+ (推荐 5.10+)
- clang/LLVM 10.0+
- libelf, zlib
- libpcap 开发库

## 编译安装

### 使用系统 libbpf (需要先安装 libbpf)

```
make
```

### 使用内置 libbpf 源码编译

本项目现在可以从源码编译 libbpf，无需系统预先安装：

```
make
```

### 安装 libbpf 到系统（需要 root 权限）

```
make install_libbpf
sudo ldconfig
```

### 安装 libbpf 到用户目录（无需 root 权限）

```
make user_install_libbpf
```

安装后，需要设置环境变量：

```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$HOME/.local/lib64
```

将上面的命令添加到 `~/.bashrc` 或 `~/.profile` 使其永久生效。

### 安装应用程序（需要 root 权限）

```
make install
```

### 安装应用程序到用户目录（无需 root 权限）

```
make user_install
```

安装后，确保 `$HOME/.local/bin` 在你的 PATH 环境变量中：

```
export PATH=$PATH:$HOME/.local/bin
```

## 使用方法

直接运行：

```
./loader -i <接口名称>
```

或者从 pcap 文件读取：

```
./loader -r <pcap文件>
```

如果已安装：

```
ebpf_pkt -i <接口名称>
```

更多选项：

```
./loader --help
```

## 命令行选项

- `-i, --interface <接口>`: 指定要监控的网络接口 (默认 eth0)
- `-r, --read <pcap文件>`: 从pcap文件读取数据包进行分析
- `-d, --duration <秒>`: 运行指定的秒数后退出 (默认无限运行)
- `-s, --stats-interval <秒>`: 每隔多少秒打印一次统计信息 (默认 5 秒)
- `-p, --packets <数量>`: 处理多少个数据包后打印统计信息 (默认 1000)
- `-c, --cleanup <秒>`: 流清理间隔，多久清理一次过期的流 (默认 10 秒)
- `-t, --threads <数量>`: 工作线程数 (默认 4)
- `-h, --help`: 显示帮助信息