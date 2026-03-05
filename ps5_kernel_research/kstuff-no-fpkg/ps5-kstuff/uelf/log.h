#pragma once
#include <stdint.h>
#include <sys/types.h>
#include <stdarg.h>

#define LOG(msg) do {} while(0)
#define printf(...) do {} while(0)

void log_word(uint64_t word);
static inline void uelf_write_log(const char* data, size_t sz) { (void)data; (void)sz; }
static inline int puts(const char *str) { (void)str; return 0; }
static inline void uelf_write_logf(const char* format, ...) { (void)format; }
