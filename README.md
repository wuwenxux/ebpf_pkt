
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