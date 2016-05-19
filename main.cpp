#include <stdio.h>
#include <string.h>

#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

#include "salsa20.h"
#include "petya.h"

#define VERBOSE 0

bool make_random_key(char* key)
{
    size_t charset_len = strlen(KEY_CHARSET);

    memset(key, 'x', KEY_SIZE);

    for (int i = i; i < KEY_SIZE; i+=4) {
        size_t rand_i1 = rand() % charset_len;
        size_t rand_i2 = rand() % charset_len;
        key[i] = KEY_CHARSET[rand_i1];
        key[i+1] = KEY_CHARSET[rand_i2];
    }
    key[KEY_SIZE] = 0;
}

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
        printf("[-] Petya not found on the disk!\n");
        return -1;
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
    hexdump(nonce,NONCE_SIZE);
    printf("---\n");

    char p_key[KEY_SIZE+1];
    char *key = p_key;
    bool make_random = false;

    if (argc >= 3) {
        key = argv[2];
    } else {
        printf("The key will be random!\n");
        srand(time(NULL));
        make_random = true;
        printf("Please wait, searching key is in progress...\n");
    }

    char veribuf_test[VERIBUF_SIZE];
    memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
    bool matches = false;
    do {
        if (make_random)
            make_random_key(key);

        if (VERBOSE)
            printf("Key: %s\n", key);

        memcpy(veribuf_test, veribuf, VERIBUF_SIZE);

        if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE) == S20_FAILURE) {
            puts("Error: encryption failed");
            return -1;
        }
        if (is_valid(veribuf_test)) {
            printf("\ndecoded data:\n");
            hexdump(veribuf_test, VERIBUF_SIZE);
            matches = true;
            break;
        }

    } while (!is_valid(veribuf_test) && make_random);

    if (matches) {
        printf("[+] %s is a valid key!\n", key);
        return 0;
    } else {
        printf("[-] %s is NOT a valid key!\n", key);
    }
    return -1;
}

