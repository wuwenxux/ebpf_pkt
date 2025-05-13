#!/bin/bash

# 检查输入参数
if [ $# -ne 1 ]; then
  echo "用法: $0 <pcap文件>"
  exit 1
fi

PCAP_FILE="$1"

# 检查文件是否存在
if [ ! -f "$PCAP_FILE" ]; then
  echo "错误: 文件 $PCAP_FILE 不存在"
  exit 1
fi

# 统计总数据包数
total_packets() {
  capinfos "$PCAP_FILE" 2>/dev/null | grep "Number of packets = "|awk '{print $5}'
  # 如果未安装capinfos，可改用: tshark -r "$PCAP_FILE" -q -z io,stat,0 | awk '/^0/{print $6}'
}

# 获取统计结果
TOTAL=$(total_packets)
TCP_COUNT=$(tshark -r "$PCAP_FILE" -q -z conv,tcp -l 2>/dev/null | awk '/^[0-9]+/{count++} END{print count}')
UDP_COUNT=$(tshark -r "$PCAP_FILE" -q -z conv,udp -l 2>/dev/null | awk '/^[0-9]+/{count++} END{print count}')

# 输出报告
echo "===== 深度流量分析报告 ====="
echo "输入文件    : $PCAP_FILE"
echo "总数据包数  : $TOTAL"
echo "TCP流数量   : $TCP_COUNT"
echo "UDP流数量   : $UDP_COUNT"