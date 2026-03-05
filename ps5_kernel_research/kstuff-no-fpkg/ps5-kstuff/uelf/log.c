#include "log.h"
#include "shared_area.h"
#include "utils.h"

uint64_t log[512];
uint64_t* p_log = log;

void log_word(uint64_t word)
{
    if(p_log != log + sizeof(log) / sizeof(*log))
        *p_log++ = word;
}

void uelf_write_log(const char* data, size_t sz)
{
    (void)data;
    (void)sz;
}

void _putchar(char character)
{
    (void)character;
}

int puts(const char *str)
{
    (void)str;
    return 0;
}

void uelf_write_logf(const char* format, ...)
{
    (void)format;
}
