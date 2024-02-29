/*
    gcc decrypt_rsapubkey.c chacha20.c -o decrypt_rsapubkey -lssl -lcrypto
*/
#include <stdio.h>
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
    if(argc < 3) {
        fprintf(stderr, "Usage: %s <KEY_HEXA> <ENC_RSAPUBKEY_HEXA>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[1]) != 64) {
        fprintf(stderr, "Key must be 64 (32-bytes) hexa chars string\n");
        return 1;
    }

    if (strlen(argv[2]) != 540) {
        fprintf(stderr, "RSA pubkey must be 540 (270 bytes) hexa chars string\n");
        return 1;
    }
    
    char g_FirmwareSeed[32] = {0};
    char g_RSA_PubKey[270] = {0};
    char *pos = argv[1];
    for (size_t i = 0; i < sizeof g_FirmwareSeed; i++) {
        sscanf(pos, "%2hhx", &g_FirmwareSeed[i]);
        pos += 2;
    }
    pos = argv[2];
    for (size_t i = 0; i < sizeof g_RSA_PubKey; i++) {
        sscanf(pos, "%2hhx", &g_RSA_PubKey[i]);
        pos += 2;
    }
    
    EVP_MD_CTX *mdctx;
    unsigned char *md1 = NULL;
    unsigned char *md2 = NULL;
    
    if((mdctx = EVP_MD_CTX_new()) == NULL)
        return 1;

    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        return 1;

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed + 3, 29) != 1)
        return 1;

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed, 3) != 1)
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

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed + 1, 31) != 1)
        return 1;

    if(EVP_DigestUpdate(mdctx, (unsigned char*)g_FirmwareSeed, 1) != 1)
        return 1;

    if((md2 = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        return 1;

    if(EVP_DigestFinal_ex(mdctx, md2, NULL) != 1)
        return 1;

    EVP_MD_CTX_free(mdctx);

    printhex(md2, 32);
    printf("\n");

    //
    // ChaCha20
    //

    struct chacha20_context ctx;
    chacha20_init_context(&ctx, md1, md2);
    chacha20_xor(&ctx, g_RSA_PubKey, 270);

    printf("BER-encoded pub key:\n");
    printhex(g_RSA_PubKey, 270);
    printf("\n");

    return 0;
}