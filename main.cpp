#include <stdio.h>
#include <string.h>

#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */
#include <vector>
#include <string>

#include "salsa20.h"
#include "petya.h"

#define VERBOSE 0
#define EXPANDED_KEY_LENGTH 32

bool makeUserKey(char* key, size_t buf_size)
{
    const size_t user_key_size = KEY_SIZE/2;
    if (key == NULL || buf_size < user_key_size) {
        return false;
    }

    size_t charset_len = strlen(KEY_CHARSET);
    memset(key, 'x', user_key_size);

    for (int i = 0; i < KEY_SIZE; i+=2) {
        static size_t rand_i1 = 0;
        static size_t rand_i2 = 0;
        rand_i1 = (rand_i1 + rand()) % charset_len;
        key[i] = KEY_CHARSET[rand_i1];
    }
    key[user_key_size] = 0;

    return true;
}

bool makeFullPetyaKey(char* key, size_t buf_size, std::string cleanKey16)
{
    if (buf_size < EXPANDED_KEY_LENGTH) {
        printf("Buffer is too small\n");
        return false;
    }
    if (cleanKey16.size() * 2 != EXPANDED_KEY_LENGTH) {
        printf("Invalid key\n");
        return false;
    }
    for (unsigned i = 0; i < cleanKey16.size(); ++i) {
        key[i * 2 + 0] = uint8_t(cleanKey16[i]) + 0x7a;
        key[i * 2 + 1] = uint8_t(cleanKey16[i]) * 2;
    }
    return true;
}

std::string petyaKeyToUserKey(char *key)
{
    size_t userKeyLen = KEY_SIZE/2;
    char userKey[userKeyLen + 1];
    for (size_t i = 0, j = 0; i < KEY_SIZE; i+=2, j++) {
        userKey[j] = key[i] - 0x7a;
    }
    userKey[userKeyLen] = 0;
    return userKey;
}

bool make_random_key(char* key, size_t buf_size)
{
    char userKey[KEY_SIZE];
    if (!makeUserKey(userKey, buf_size)) return false;

    return makeFullPetyaKey(key, buf_size, userKey);
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
    hexdump(nonce, NONCE_SIZE);
    printf("---\n");

    char p_key[KEY_SIZE+1];
    char *key = p_key;
    bool make_random = false;
    size_t veri_size = VERIBUF_SIZE;

    if (argc >= 3) {
        makeFullPetyaKey(p_key, sizeof(p_key), argv[2]);
        std::string userKey = petyaKeyToUserKey(key);
        printf("Key:\n%s\n", userKey.c_str());
        hexdump(p_key, KEY_SIZE);
    } else {
        printf("The key will be random!\n");
        veri_size = 3; //the size that will be encrypted during tests
        srand(time(NULL));
        make_random = true;
        printf("Please wait, searching key is in progress...\n");
    }

    char veribuf_test[VERIBUF_SIZE];
    memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
    bool matches = false;
    size_t unmatching;
    do {

        if (make_random){
            if (make_random_key(p_key, sizeof(p_key)) == false)
                return -1;
        }
        memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
        if (!s20_crypt_256bit((uint8_t *) key, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE)) {
            puts("Error: encryption failed");
            return -1;
        }
        if ((unmatching = count_unmatching(veribuf_test, veri_size)) == 0) {
            if (veri_size == VERIBUF_SIZE) { //full length already checked
                matches = true;
                break;
            }

            std::string userKey = petyaKeyToUserKey(key);
            printf("[*] Key candidate: %s\n", userKey.c_str());

            memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
            if (!s20_crypt_256bit((uint8_t *) key, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE)) {
                puts("Error: encryption failed");
                return -1;
            }
            if ((unmatching = count_unmatching(veribuf_test, VERIBUF_SIZE)) == 0) {
                printf("[+] Doublecheck passed\n");
                matches = true;
                break;
            } else {
                printf("[-] Doublecheck failed, searching again...\n");
            }
            printf("unmatching: %d\n", unmatching);
        }

    } while (make_random);

    printf("\ndecoded data:\n");
    hexdump(veribuf_test, VERIBUF_SIZE);
    printf("unmatching: %d\n", unmatching);

    std::string userKey = petyaKeyToUserKey(key);
    if (matches) {
        printf("[+] %s is a valid key!\n", userKey.c_str());
        return 0;
    } else {
        printf("[-] %s is NOT a valid key!\n", userKey.c_str());
    }
    return -1;
}

