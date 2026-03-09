# eBPF Packet

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 简介

本项目是一个基于 eBPF 技术的高性能网络数据包捕获与流量分析工具。利用 eBPF XDP 程序在内核空间高效捕获网络流量，结合多线程用户态处理，实现低开销的实时网络监控，支持自定义过滤规则和流量统计。

## 主要功能

- 使用 eBPF XDP 程序高效捕获数据包
- 支持实时网络接口监控和 pcap 文件离线分析
- 实时捕获 IPv4/TCP/UDP 协议流量
- 流量按流分组统计（包计数、字节数）
- 多线程处理以提高性能
- 定期输出统计信息
- 支持保存捕获结果到 PCAP 格式文件

## 系统要求

- Linux 内核 ≥ 5.5（推荐 5.10+）
- Clang/LLVM ≥ 10.0
- libelf、zlib
- libpcap 开发库

## 编译安装

### 安装依赖

```bash
sudo apt-get update && sudo apt-get install -y \
    clang llvm libelf-dev libpcap-dev zlib1g-dev
```

### 编译

```bash
make
```

项目内置了 libbpf 源码，无需系统预先安装 libbpf。

### 安装 libbpf 到系统（需要 root 权限）

```bash
make install_libbpf
sudo ldconfig
```

### 安装 libbpf 到用户目录（无需 root 权限）

```bash
make user_install_libbpf
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$HOME/.local/lib64
```

将 `export` 命令添加到 `~/.bashrc` 或 `~/.profile` 使其永久生效。

### 安装应用程序（需要 root 权限）

```bash
make install
```

### 安装应用程序到用户目录（无需 root 权限）

```bash
make user_install
export PATH=$PATH:$HOME/.local/bin
```

## 使用方法

监控网络接口：

```bash
./loader -i <接口名称>
```

从 pcap 文件离线分析：

```bash
./loader -r <pcap文件>
```

若已安装到系统：

```bash
ebpf_pkt -i <接口名称>
```

查看所有选项：

```bash
./loader --help
```

## 命令行选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-i, --interface <接口>` | 指定要监控的网络接口 | eth0 |
| `-r, --read <pcap文件>` | 从 pcap 文件读取数据包进行分析 | - |
| `-d, --duration <秒>` | 运行指定秒数后退出 | 无限运行 |
| `-s, --stats-interval <秒>` | 打印统计信息的时间间隔 | 5 |
| `-p, --packets <数量>` | 处理多少个数据包后打印统计信息 | 1000 |
| `-c, --cleanup <秒>` | 过期流的清理间隔 | 10 |
| `-t, --threads <数量>` | 工作线程数 | 4 |
| `-h, --help` | 显示帮助信息 | - |

## 联系方式

- 邮箱：wwx0306@foxmail.com
- 项目地址：https://github.com/wuwenxux/ebpf_pkt
