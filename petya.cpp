#include <stdio.h>
#include <string.h>
#include "petya.h"

#define HTTP_OFFSET 0x29


bool is_infected(FILE *fp)
{
    char Bootloader[] = \
    "\xfa\x66\x31\xc0\x8e\xd0\x8e\xc0\x8e\xd8\xbc\x00\x7c\xfb\x88\x16"
    "\x93\x7c\x66\xb8\x20\x00\x00\x00\x66\xbb\x22\x00\x00\x00\xb9\x00"
    "\x80\xe8\x14\x00\x66\x48\x66\x83\xf8\x00\x75\xf5\x66\xa1\x00\x80"
    "\xea\x00\x80\x00\x00";

    const size_t bootloader_offset = 0;
    bool has_bootloader = check_pattern(fp, bootloader_offset, Bootloader, sizeof(Bootloader));
    if (has_bootloader) printf("[+] Petya bootloader detected!\n");

    char http_pattern[] = "http://";
    const size_t http_offset = ONION_SECTOR_NUM * SECTOR_SIZE + HTTP_OFFSET;
    bool has_http = check_pattern(fp, http_offset, http_pattern, sizeof(http_pattern));
    if (has_http) printf("[+] Petya http address detected!\n");

    return has_bootloader || has_http;
}

char* fetch_veribuf(FILE *fp)
{
    size_t offset = VERIBUF_SECTOR_NUM * SECTOR_SIZE;
    return fetch_data(fp, offset, VERIBUF_SIZE);
}

char* fetch_nonce(FILE *fp)
{
    size_t offset = ONION_SECTOR_NUM * SECTOR_SIZE + NONCE_OFFSET;
    return fetch_data(fp, offset, NONCE_SIZE);
}

size_t count_unmatching(char *veribuf, size_t veri_size = VERIBUF_SIZE)
{
    veri_size = (veri_size > VERIBUF_SIZE) ? VERIBUF_SIZE : veri_size;
    veri_size = (veri_size == 0) ? 1 : veri_size;
    size_t unmatching = 0;
    for (size_t i = 0; i < veri_size; i++) {
        if (veribuf[i] != VERIFICATION_CHAR) unmatching++;
    }
    return unmatching;
}

