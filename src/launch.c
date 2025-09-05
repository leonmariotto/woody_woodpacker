/*
 * Launch routine: decryption and execve
 * Copy woody binary, change jump addr of _start symbol to launch addr.
 * Add a section for elf_data.
 * Fill key[], elf_data pointer, and elf_size symbol with correct values.
 * */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((__used__)) uint8_t key[16] = {42};
__attribute__((__used__)) uint8_t *elf_data = (uint8_t*)0x42424242;
__attribute__((__used__)) size_t elf_size = 42;
__attribute__((__used__)) uint64_t elf_size_vaddr = 42;

#define _GNU_SOURCE
#include <linux/memfd.h>
#include <sys/syscall.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "tinycrypt/aes.h"
#include "tinycrypt/constants.h"

static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}

__attribute__((__used__)) int decrypt_elf(uint8_t *buf, size_t size, uint8_t *key)
{
    struct tc_aes_key_sched_struct s;
    int r = 0;

    // printf("%s:%d elf_data=%p\n", __func__, __LINE__, elf_data);
    r = tc_aes128_set_decrypt_key(&s, key);
    if (r != TC_CRYPTO_SUCCESS) {
        fprintf(stderr, "Failed to set decryption key\n");
    }
    // printf("%s:%d elf_data=%p\n", __func__, __LINE__, elf_data);
    if (r == TC_CRYPTO_SUCCESS) {
        if (size % 16 != 0)
            fprintf(stderr, "Error, size should be %% 16\n");
        size_t offset = 0;
        while (r == TC_CRYPTO_SUCCESS && offset < size) {
            //if (offset < 64)
            //    printf("%s:%d elf_data=%p &buf[offset]=%p\n", __func__, __LINE__, elf_data, &buf[offset]);
            // printf("Size left = %zu\n", size - offset);
            r = tc_aes_decrypt(&buf[offset], &buf[offset], &s);
            if (r != TC_CRYPTO_SUCCESS) {
                fprintf(stderr, "Failed to encrypt\n");
            }
            offset += 16;
        }
    }
    // printf("%s:%d elf_data=%p\n", __func__, __LINE__, elf_data);
    return (r == TC_CRYPTO_SUCCESS ? 0 : -1);
}

__attribute__((__used__)) int exec_elf(uint8_t *elf, size_t elf_size, char **env) {
    int fd = memfd_create("packed", 0);
    if (fd == -1) {
        perror("memfd_create");
        exit(1);
    }

    if (write(fd, elf, elf_size) != (ssize_t)elf_size) {
        perror("write");
        exit(1);
    }

    // Execute it
    fexecve(fd, (char *const[]){ "packed", NULL }, env);

    // Should not be here
    perror("fexecve");
    return 1;
}

void hex_dump(uint8_t *data, size_t size, char *label)
{
    // %%%%%%%%%% DUMP %%%%%%%%%%%%
    for (size_t i = 0 ; i < size; i++) {
        if (i % 32 == 0)
            printf("\n%s: %08lx: ", label, (uint64_t)i);
        printf("%02x ", data[i]);
        i++;
    }
}

__attribute__((__used__)) int launch(int ac, char **av, char **env)
{
    //printf("Hello World!\n");
    //printf("&elf_data=%p elf_data=%p elf_size=%zu key=%p elf_size_vaddr=%lx\n", &elf_data, elf_data, elf_size, key, elf_size_vaddr);
    uintptr_t base_addr = (uintptr_t)&elf_size - (uintptr_t)elf_size_vaddr;
    uint8_t *runtime_elf_data =  (uint8_t*)elf_data + (uintptr_t)base_addr;
    //printf("K=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
    //    key[0], key[1], key[2], key[3],
    //    key[4+0], key[4+1], key[4+2], key[4+3],
    //    key[8+0], key[8+1], key[8+2], key[8+3],
    //    key[12+0], key[12+1], key[12+2], key[12+3]);

    // hex_dump(runtime_elf_data, 64, "BEFORE DECRYPTION");
    int r = decrypt_elf(runtime_elf_data, elf_size, (uint8_t*)key);
    if (r == 0) {
        // hex_dump(runtime_elf_data, 64, "AFTER DECRYPTION");
        exec_elf(runtime_elf_data, elf_size, env);
    }
    // never reached
    return 42;
}
