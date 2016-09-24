#pragma once
#include <stdio.h>
#include "util.h"

#define SECTOR_SIZE 0x200
#define NONCE_OFFSET 0x21

#define VERIBUF_SIZE SECTOR_SIZE
#define NONCE_SIZE 8

#define VERIBUF_SECTOR_NUM 55
#define ONION_SECTOR_NUM 54

#define VERIFICATION_CHAR 0x7

#define KEY_SIZE 16
const char KEY_CHARSET[] = "123456789abcdefghijkmnopqrstuvwxABCDEFGHJKLMNPQRSTUVWX";
bool is_infected(FILE *fp);

char* fetch_veribuf(FILE *fp);
char* fetch_nonce(FILE *fp);

size_t count_unmatching(char* veribuf, size_t veri_size);
