#!/bin/bash
# loader_flow_test.sh - 使用loader程序测试统计流数量

# 检查命令行参数
if [ $# -lt 1 ]; then
  echo "用法: $0 <pcap文件路径> [pcap文件路径2] ..."
  echo "示例: $0 ./test/20231022.pcap ./test/20231014.pcap"
  exit 1
fi

# 创建结果目录
RESULT_DIR="./test/results"
mkdir -p "$RESULT_DIR"

# 创建汇总文件
SUMMARY_FILE="$RESULT_DIR/flow_summary.txt"
echo "流量统计汇总 ($(date))" > "$SUMMARY_FILE"
echo "=======================================" >> "$SUMMARY_FILE"
printf "%-30s %-10s %-10s %-15s\n" "文件" "TCP流" "UDP流" "总数据包" >> "$SUMMARY_FILE"
echo "=======================================" >> "$SUMMARY_FILE"

# 处理每个pcap文件
for PCAP_FILE in "$@"; do
  # 检查文件是否存在
  if [ ! -f "$PCAP_FILE" ]; then
    echo "错误: 文件不存在: $PCAP_FILE"
    continue
  fi

  FILENAME=$(basename "$PCAP_FILE")
  echo "处理: $FILENAME"
  
  # 创建输出文件
  OUTPUT_FILE="$RESULT_DIR/${FILENAME%.pcap}_analysis.txt"
  
  # 运行loader分析流量
  echo "运行loader分析流量..."
  sudo ./loader -r "$PCAP_FILE" > "$OUTPUT_FILE"
  
  # 从输出提取关键信息
  TCP_FLOWS=$(grep -E "TCP Flows:[ \t]*([0-9]+)" "$OUTPUT_FILE" | grep -o "[0-9]\+" | head -1)
  TCP_FLOWS=${TCP_FLOWS:-0}
  
  UDP_FLOWS=$(grep -E "UDP Flows:[ \t]*([0-9]+)" "$OUTPUT_FILE" | grep -o "[0-9]\+" | head -1)
  UDP_FLOWS=${UDP_FLOWS:-0}
  
  TOTAL_FLOWS=$((TCP_FLOWS + UDP_FLOWS))
  
  TOTAL_PACKETS=$(grep -E "Total Packets:[ \t]*([0-9]+)" "$OUTPUT_FILE" | grep -o "[0-9]\+" | head -1)
  TOTAL_PACKETS=${TOTAL_PACKETS:-0}
  
  # 格式化数字
  TCP_FLOWS_FMT=$(printf "%'d" $TCP_FLOWS)
  UDP_FLOWS_FMT=$(printf "%'d" $UDP_FLOWS)
  TOTAL_FLOWS_FMT=$(printf "%'d" $TOTAL_FLOWS)
  TOTAL_PACKETS_FMT=$(printf "%'d" $TOTAL_PACKETS)
  
  # 显示结果
  echo "分析结果:"
  echo "- TCP流数: $TCP_FLOWS_FMT"
  echo "- UDP流数: $UDP_FLOWS_FMT"
  echo "- 总流数: $TOTAL_FLOWS_FMT"
  echo "- 总数据包数: $TOTAL_PACKETS_FMT"
  echo "详细分析已保存至: $OUTPUT_FILE"
  echo
  
  # 添加到汇总文件
  printf "%-30s %-10s %-10s %-15s\n" "$FILENAME" "$TCP_FLOWS" "$UDP_FLOWS" "$TOTAL_PACKETS" >> "$SUMMARY_FILE"
done

echo "所有分析结果已保存至: $RESULT_DIR"
echo "汇总信息: $SUMMARY_FILE"
cat "$SUMMARY_FILE"