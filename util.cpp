#include "util.h"

void hexdump(char* in_buf, const size_t in_size)
{
    for (int i = 0; i < in_size; i++) {
        printf("%02x ", (uint8_t) in_buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

char* fetch_data(FILE *fp, const size_t offset, const size_t in_size)
{
    char* in_buf = new char[in_size];
    memset(in_buf, 0, in_size);
    fseek(fp, offset, SEEK_SET);
    size_t read = fread(in_buf, 1, in_size, fp);
    if (read != in_size) {
        printf("Error, read = %d\n", read);
        return NULL;
    }
    return in_buf;
}

bool check_pattern(FILE *fp, size_t offset, const char *cmp_buf, size_t cmp_size)
{
    char out_buf[0x400];
    cmp_size = (cmp_size > sizeof(out_buf)) ? sizeof(out_buf) : cmp_size;

    fseek(fp, offset, SEEK_SET);
    size_t read = fread(out_buf, 1, cmp_size, fp);

    if (read != cmp_size) {
        printf("Error, read = %d\n", read);
        return false;
    }

    if (memcmp(out_buf, cmp_buf, cmp_size-1) == 0) {
        return true;
    }
    return false;
}

