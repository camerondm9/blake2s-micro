//  BLAKE2 - size-optimized implementations
//
//  Copyright 2012, Samuel Neves <sneves@dei.uc.pt> (original work)
//  Copyright 2018, Ayke van Laethem
//
//  You may use this under the terms of the CC0, the OpenSSL Licence, or
//  the Apache Public License 2.0, at your option. The terms of these
//  licenses can be found at:
//
//  - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
//  - OpenSSL license   : https://www.openssl.org/source/license.html
//  - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
//
//  More information about the BLAKE2 hash function can be found at
//  https://blake2.net.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "blake2s.h"

const uint8_t data[] = "The quick brown fox jumps over the lazy dog";

void test(const uint8_t *data, size_t len) {
    unsigned char result[32];

    blake2s_state S;
    blake2s_init(&S);
    blake2s_update(&S, data, len);
    blake2s_final(&S, &result);

    for (size_t i = 0; i < sizeof(result); i++) {
        printf("%02x", result[i]);
    }
    printf("\n");
}

#if BLAKE2S_KEYED
void test_key(const uint8_t *key, size_t len_key, const uint8_t *data, size_t len_data) {
    unsigned char result[32];

    blake2s_state S;
    blake2s_init_key(&S, key, len_key);
    blake2s_update(&S, data, len_data);
    blake2s_final(&S, &result);

    for (size_t i = 0; i < sizeof(result); i++) {
        printf("%02x", result[i]);
    }
    printf("\n");
}
#endif

int main(int argc, char **argv) {
    if (argc > 1) {
        for (size_t i = 1; i < argc; i++) {
            char *colon = strchr(argv[i], ':');
            if (colon == NULL) {
                size_t len = strlen(argv[i]) / 2;
                //Read hex-encoded data
                uint8_t *buf = malloc(len);
                for (size_t j = 0; j < len; j++) {
                    sscanf(&argv[i][j*2], "%2hhx", &buf[j]);
                };
                test(buf, len);
                free(buf);
            } else {
                #if BLAKE2S_KEYED
                //Replace colon with null to split the string
                *colon++ = 0;
                size_t len_key = strlen(argv[i]) / 2;
                size_t len_data = strlen(colon) / 2;
                //Read hex-encoded data
                uint8_t *buf_key = malloc(len_key);
                for (size_t j = 0; j < len_key; j++) {
                    sscanf(&argv[i][j*2], "%2hhx", &buf_key[j]);
                };
                uint8_t *buf_data = malloc(len_data);
                for (size_t j = 0; j < len_data; j++) {
                    sscanf(&colon[j*2], "%2hhx", &buf_data[j]);
                };
                test_key(buf_key, len_key, buf_data, len_data);
                free(buf_data);
                free(buf_key);
                #else
                printf("skip: Keyed hash support disabled.\n");
                #endif
            }
        }
    } else {
        test(data, sizeof(data) - 1);
        test(NULL, 0);
    }
}
