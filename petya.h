#pragma once
#include <stdio.h>
#include "util.h"

#define SECTOR_SIZE 0x200
#define NONCE_OFFSET 0x21
#define KEY_OFFSET 0x1
#define FLAG_OFFSET 0

#define VERIBUF_SIZE SECTOR_SIZE
#define NONCE_SIZE 8

#define VERIBUF_SECTOR_NUM 33
#define ONION_SECTOR_NUM 32

#define VERIFICATION_CHAR 0x7

#define KEY_SIZE 32
const char KEY_CHARSET[] = "123456789abcdefghijkmnopqrstuvwxABCDEFGHJKLMNPQRSTUVWX";
bool is_infected(FILE *fp);

// check the flag informing if the disk was encrypted:
bool is_encrypted(FILE *fp);

char* fetch_veribuf(FILE *fp);
char* fetch_nonce(FILE *fp);

// fetch the key - if it was not erased yet:
char* fetch_key(FILE *fp);

size_t count_unmatching(char* veribuf, size_t veri_size);
