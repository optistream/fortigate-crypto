/*
    gcc decrypt_rootfs.c chacha20.c -o decrypt_rootfs -lssl -lcrypto
*/
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "chacha20.h"

void printhex(unsigned char* data, int len) {
    int i = 0;
    for(; i < len; i++) {
        printf("%02X", data[i]);
    }
}

int main(int argc, char **argv)
{
    if(argc < 4) {
        fprintf(stderr, "Usage: %s rootfs.tgz rootfs.tgz.encrypted <KEY_HEXA>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[3]) != 64) {
        fprintf(stderr, "Key must be 64 (32-bytes) hexa chars string\n");
        return 1;
    }
    
    char g_FirmwareSeed[32] = {0};
    char *pos = argv[3];
    for (size_t i = 0; i < sizeof g_FirmwareSeed; i++) {
        sscanf(pos, "%2hhx", &g_FirmwareSeed[i]);
        pos += 2;
    }
    
    EVP_MD_CTX *mdctx;
    unsigned char *md1 = NULL;
    unsigned char *md2 = NULL;

    if((mdctx = EVP_MD_CTX_new()) == NULL)
        return 1;

    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        return 1;

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed + 4, 28) != 1)
        return 1;

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed, 4) != 1)
        return 1;

    if((md1 = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        return 1;

    if(EVP_DigestFinal_ex(mdctx, md1, NULL) != 1)
        return 1;

    EVP_MD_CTX_free(mdctx);

    printhex(md1, 32);
    printf("\n");

    if((mdctx = EVP_MD_CTX_new()) == NULL)
        return 1;

    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        return 1;

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed + 5, 27) != 1)
        return 1;

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed, 5) != 1)
        return 1;

    if((md2 = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        return 1;

    if(EVP_DigestFinal_ex(mdctx, md2, NULL) != 1)
        return 1;

    EVP_MD_CTX_free(mdctx);

    printhex(md2, 32);
    printf("\n");

    //
    // ChaCha20 (custom)
    //

    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("rootfs size: %u\n", fsize);
    char *data = malloc(fsize);
    memset(data, 0xFF, fsize);
    fread(data, fsize, 1, f);
    fclose(f);

    printf("Encrypting rootfs...\n");
    struct chacha20_context ctx;
    chacha20_init_context(&ctx, md1, md2);
    chacha20_xor(&ctx, data, fsize);

    printf("Writing to %s...\n", argv[2]);
    FILE *f_out = fopen(argv[2], "wb");
    fwrite(data, fsize, 1, f_out);

    // Add fake trailing signature
    char trail_sig[256];
    memset(trail_sig, 0xFF, sizeof(trail_sig));
    fwrite(trail_sig, sizeof(trail_sig), 1, f_out);
    fclose(f_out);

    return 0;
}