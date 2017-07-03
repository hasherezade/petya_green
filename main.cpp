#include <stdio.h>
#include <string.h>

#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

#include "salsa20.h"
#include "petya.h"

#define VERBOSE 0

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Supply the disk dump as a parameter!\n");
        return -1;
    }
    char* filename = argv[1];
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("Cannot open file %s\n", filename);
        return -1;
    }

    if (is_infected(fp)) {
        printf("[+] Petya FOUND on the disk!\n");
    } else {
        //TODO: add signature for EternalPetya
        //return -1;
    }
    bool disk_encrypted = true;
    if (!is_encrypted(fp)) {
        printf("[*] The disk is not encrypted.\n");
        disk_encrypted = false;
    }
    char* veribuf = fetch_veribuf(fp);
    char* nonce = fetch_nonce(fp);
    if (!nonce || !veribuf) {
        printf("Cannot fetch nonce or veribuf!\n");
        return -1;
    }
    printf("---\n");
    printf("verification data:\n");
    hexdump(veribuf, VERIBUF_SIZE);

    printf("nonce:\n");
    hexdump(nonce, NONCE_SIZE);
    printf("---\n");

    char p_key[KEY_SIZE+1];
    char *key = p_key;
    bool make_random = false;
    size_t veri_size = VERIBUF_SIZE;

    if (!disk_encrypted) {
        key = fetch_key(fp);
        printf("key:\n");
        hexdump(key, KEY_SIZE);
        printf("---\n");
    } else {
        printf("Please supply the disk dump BEFORE the encryption\n");
        return -1;
    }

    char veribuf_test[VERIBUF_SIZE];
    memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
    bool matches = false;
    size_t unmatching = 0;

    memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
    if (s20_crypt((uint8_t *) key, S20_KEYLEN_256, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, veri_size) == S20_FAILURE) {
        puts("Error: encryption failed");
        return -1;
    }
    unmatching = count_unmatching(veribuf_test, veri_size);
    printf("\ndecoded data:\n");
    hexdump(veribuf_test, VERIBUF_SIZE);
    printf("unmatching: %d\n", unmatching);

    printf("Test back:\n");

    if (s20_crypt((uint8_t *) key, S20_KEYLEN_256, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, veri_size) == S20_FAILURE) {
        puts("Error: encryption failed");
        return -1;
    }
    unmatching = count_unmatching(veribuf_test, veri_size);
    printf("\ndecoded data:\n");
    hexdump(veribuf_test, VERIBUF_SIZE);
    printf("unmatching: %d\n", unmatching);
    if (unmatching == 0) {
        printf("[+] %s is a valid key!\n", key);
        return 0;
    } else {
        printf("[-] %s is NOT a valid key!\n", key);
    }
    return -1;
}

