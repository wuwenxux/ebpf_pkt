#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>

// 全局日志级别 - 根据编译模式设置默认级别
#ifdef DEBUG
log_level_t global_log_level = LOG_LEVEL_DEBUG;  // Debug模式：显示所有日志
#else
log_level_t global_log_level = LOG_LEVEL_WARN;   // Release模式：只显示警告和错误
#endif

// 日志输出文件
static FILE *log_output = NULL;
static FILE *log_file = NULL;

// 日志级别字符串
static const char *level_strings[] = {
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG"
};

// 日志颜色（ANSI转义序列）
static const char *level_colors[] = {
    "\033[31m",  // ERROR - 红色
    "\033[33m",  // WARN  - 黄色
    "\033[32m",  // INFO  - 绿色
    "\033[36m"   // DEBUG - 青色
};

static const char *color_reset = "\033[0m";

void set_log_level(log_level_t level) {
    global_log_level = level;
}

log_level_t get_log_level(void) {
    return global_log_level;
}

const char* get_build_mode_log_level(void) {
#ifdef DEBUG
    return "DEBUG";
#else
    return "RELEASE";
#endif
}

void log_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    struct tm *tm_info;
    
    gettimeofday(&tv, NULL);
    
    // 转换为东八区时间 (UTC+8)
    time_t utc_time = tv.tv_sec;
    time_t beijing_time = utc_time + 8 * 3600; // 东八区 = UTC+8
    tm_info = gmtime(&beijing_time);
    
    snprintf(buffer, size, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             tv.tv_usec / 1000);
}

void log_format_level(log_level_t level, char *buffer, size_t size) {
    if (level < 0 || level >= sizeof(level_strings) / sizeof(level_strings[0])) {
        snprintf(buffer, size, "UNKNOWN");
        return;
    }
    snprintf(buffer, size, "%s", level_strings[level]);
}

void log_msg(log_level_t level, const char *fmt, ...) {
    if (level > global_log_level) {
        return;
    }
    
    char timestamp[64];
    char level_str[16];
    va_list args;
    
    log_timestamp(timestamp, sizeof(timestamp));
    log_format_level(level, level_str, sizeof(level_str));
    
    // 选择输出目标
    FILE *output = log_file ? log_file : (log_output ? log_output : stderr);
    
    // 输出带颜色的日志（如果输出到终端）
    if (output == stderr || output == stdout) {
        fprintf(output, "%s%s%s [%s] ", 
                level_colors[level], level_str, color_reset, timestamp);
    } else {
        fprintf(output, "[%s] [%s] ", level_str, timestamp);
    }
    
    va_start(args, fmt);
    vfprintf(output, fmt, args);
    va_end(args);
    
    fprintf(output, "\n");
    fflush(output);
}

void log_error(const char *fmt, ...) {
    va_list args;
    char timestamp[64];
    char level_str[16];
    
    log_timestamp(timestamp, sizeof(timestamp));
    log_format_level(LOG_LEVEL_ERROR, level_str, sizeof(level_str));
    
    FILE *output = log_file ? log_file : (log_output ? log_output : stderr);
    
    if (output == stderr || output == stdout) {
        fprintf(output, "%s%s%s [%s] ", 
                level_colors[LOG_LEVEL_ERROR], level_str, color_reset, timestamp);
    } else {
        fprintf(output, "[%s] [%s] ", level_str, timestamp);
    }
    
    va_start(args, fmt);
    vfprintf(output, fmt, args);
    va_end(args);
    
    fprintf(output, "\n");
    fflush(output);
}

void log_warn(const char *fmt, ...) {
    if (LOG_LEVEL_WARN > global_log_level) return;
    
    va_list args;
    char timestamp[64];
    char level_str[16];
    
    log_timestamp(timestamp, sizeof(timestamp));
    log_format_level(LOG_LEVEL_WARN, level_str, sizeof(level_str));
    
    FILE *output = log_file ? log_file : (log_output ? log_output : stderr);
    
    if (output == stderr || output == stdout) {
        fprintf(output, "%s%s%s [%s] ", 
                level_colors[LOG_LEVEL_WARN], level_str, color_reset, timestamp);
    } else {
        fprintf(output, "[%s] [%s] ", level_str, timestamp);
    }
    
    va_start(args, fmt);
    vfprintf(output, fmt, args);
    va_end(args);
    
    fprintf(output, "\n");
    fflush(output);
}

void log_info(const char *fmt, ...) {
    if (LOG_LEVEL_INFO > global_log_level) return;
    
    va_list args;
    char timestamp[64];
    char level_str[16];
    
    log_timestamp(timestamp, sizeof(timestamp));
    log_format_level(LOG_LEVEL_INFO, level_str, sizeof(level_str));
    
    FILE *output = log_file ? log_file : (log_output ? log_output : stderr);
    
    if (output == stderr || output == stdout) {
        fprintf(output, "%s%s%s [%s] ", 
                level_colors[LOG_LEVEL_INFO], level_str, color_reset, timestamp);
    } else {
        fprintf(output, "[%s] [%s] ", level_str, timestamp);
    }
    
    va_start(args, fmt);
    vfprintf(output, fmt, args);
    va_end(args);
    
    fprintf(output, "\n");
    fflush(output);
}

void log_debug(const char *fmt, ...) {
    if (LOG_LEVEL_DEBUG > global_log_level) return;
    
    va_list args;
    char timestamp[64];
    char level_str[16];
    
    log_timestamp(timestamp, sizeof(timestamp));
    log_format_level(LOG_LEVEL_DEBUG, level_str, sizeof(level_str));
    
    FILE *output = log_file ? log_file : (log_output ? log_output : stderr);
    
    if (output == stderr || output == stdout) {
        fprintf(output, "%s%s%s [%s] ", 
                level_colors[LOG_LEVEL_DEBUG], level_str, color_reset, timestamp);
    } else {
        fprintf(output, "[%s] [%s] ", level_str, timestamp);
    }
    
    va_start(args, fmt);
    vfprintf(output, fmt, args);
    va_end(args);
    
    fprintf(output, "\n");
    fflush(output);
}

 