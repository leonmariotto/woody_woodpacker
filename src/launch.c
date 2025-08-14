/*
 * Launch routine: decryption and execve
 * Copy woody binary, change jump addr of _start symbol to launch addr.
 * Add a section for elf_data.
 * Fill key[], elf_data pointer, and elf_size symbol with correct values.
 * */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

uint8_t key[16] = {0};
uint8_t *elf_data = NULL;
size_t elf_size = 0;

#include "tinycrypt/aes.h"
#include "tinycrypt/constants.h"

int decrypt_elf(uint8_t *buf, size_t size, uint8_t *key)
{
    struct tc_aes_key_sched_struct s;
    int r = 0;

    r = tc_aes128_set_decrypt_key(&s, key);
    if (r != TC_CRYPTO_SUCCESS) {
        fprintf(stderr, "Failed to set decryption key\n");
    }
    if (r == TC_CRYPTO_SUCCESS) {
        size_t offset = 0;
        while (r == TC_CRYPTO_SUCCESS && offset < size) {
            r = tc_aes_decrypt(&buf[offset], &buf[offset], &s);
            if (r != TC_CRYPTO_SUCCESS) {
                fprintf(stderr, "Failed to encrypt\n");
            }
            offset += 16;
        }
    }
    return (r == TC_CRYPTO_SUCCESS ? 0 : -1);
}


int launch(int ac, char **av, char **env)
{
    printf("Hello Wolrd!\n");

    //printf("Decrypt elf\n");
    //r = decrypt_elf(bin, size, key);
    return 42;
}
