#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

// 日志级别枚举
typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

// 日志系统函数声明
extern log_level_t global_log_level;

// 日志系统函数
void set_log_level(log_level_t level);
log_level_t get_log_level(void);
const char* get_build_mode_log_level(void);
void log_msg(log_level_t level, const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_debug(const char *fmt, ...);

// 日志格式化函数
void log_timestamp(char *buffer, size_t size);
void log_format_level(log_level_t level, char *buffer, size_t size);



#endif /* LOGGER_H */ 