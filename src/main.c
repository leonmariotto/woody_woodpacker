/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: leon <lmariott@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/04/07 12:34:17 by leon              #+#    #+#             */
/*   Updated: 2022/06/03 14:41:59 by lmariott         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define _GNU_SOURCE
#include <linux/memfd.h>
#include <sys/syscall.h>

#include "tinycrypt/aes.h"
#include "tinycrypt/constants.h"

#include "elftool.h"
#include "elftool_transform.h"
#include "elftool_write.h"
#include "elftool_parse.h"

int boot_mode = 0;

static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}


int exec_elf(uint8_t *elf, size_t elf_size, char **env) {
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

int load_elf(char *path, uint8_t **elf, size_t *elf_size)
{
    struct stat stats;
    int fd;
    int r = 0;

    if (!path || !elf || !elf_size)
        return EINVAL;
    if ((fd = open(path, O_RDONLY)) <= 0) {
        r = EINVAL;
        fprintf(stderr, "open failed");
    }
    if (r == 0) {
        if (fstat(fd, &stats)) {
            r = EINVAL;
            fprintf(stderr, "fstat failed");
        }
    }
    if (r == 0) {
        if ((stats.st_mode & S_IFMT) != S_IFREG) {
            r = EINVAL;
            fprintf(stderr, "This is not a regular file, abort");
        }
    }
    if (r == 0) {
        *elf_size = stats.st_blocks * 512;
        if (*elf_size % 4096) {
            r = EINVAL;
            fprintf(stderr, "bin->length not aligned to pagesize");
        }
    }
    if (r == 0) {
        if (!(*elf = mmap(NULL, *elf_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE, fd, 0))) {
            r = EINVAL;
            fprintf(stderr, "mmap call failed");
        }
    }
    if (fd >= 0) {
        close(fd);
    }
    return (r);
}

int get_urandom(uint8_t *buf, size_t size)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return EIO;
    int r = read(fd, buf, size);
    if (r != (ssize_t)size)
        return EIO;
    return 0;
}

int encrypt_elf(uint8_t *buf, size_t size, uint8_t *key)
{
    struct tc_aes_key_sched_struct s;
    int r = 0;

    r = tc_aes128_set_encrypt_key(&s, key);
    if (r != TC_CRYPTO_SUCCESS) {
        fprintf(stderr, "Failed to set encryption key\n");
    }
    if (r == TC_CRYPTO_SUCCESS) {
        size_t offset = 0;
        while (r == TC_CRYPTO_SUCCESS && offset < size) {
            r = tc_aes_encrypt(&buf[offset], &buf[offset], &s);
            if (r != TC_CRYPTO_SUCCESS) {
                fprintf(stderr, "Failed to encrypt\n");
            }
            offset += 16;
        }
    }
    return (r == TC_CRYPTO_SUCCESS ? 0 : -1);
}

int main(int ac, char **av, char **env)
{
    int r = 0;
    uint8_t *target_bin = NULL;
    size_t target_size = 0;
    uint8_t key[16] = {0};

    if (ac != 2) {
        fprintf(stderr, "Usage: ./woody [target_elf]\n");
        return -1;
    }
    printf("Load target elf (%s)\n", av[1]);
    r = load_elf(av[1], &target_bin, &target_size);

    if (r == 0) {
        printf("Get random\n");
        r = get_urandom(key, 16);
        printf("K=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            key[0], key[1], key[2], key[3],
            key[4+0], key[4+1], key[4+2], key[4+3],
            key[8+0], key[8+1], key[8+2], key[8+3],
            key[12+0], key[12+1], key[12+2], key[12+3]);
    }
    if (r == 0) {
        printf("Encrypt elf\n");
        if (r == 0) {
            r = encrypt_elf(target_bin, target_size, key);
        }
    }
    elftool_t bin = {0};
    if (r == 0) {
        printf("Parse woody elf\n");
        r = elftool_load(&bin, av[0]);
        if (r == 0) {
            r = elftool_parse(&bin);
        }
    }
    if (r == 0) {
        printf("Inject new section\n");
        elftool_transform_t trans = {
            .type = NM_SECTION_INJECT,
            .code = target_bin,
            .code_len = target_size,
        };
        r = elftool_transform_section_injection(&bin, &trans);
    }
    if (r == 0) {
        printf("Write woody output\n");
        r = elftool_write(&bin, "woody_out");
    }

    return (r);
}
