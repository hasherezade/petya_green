#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void hexdump(char* in_buf, const size_t in_size);
char* fetch_data(FILE *fp, const size_t offset, const size_t in_size);

bool check_pattern(FILE *fp, size_t offset, const char *cmp_buf, size_t cmp_size);

