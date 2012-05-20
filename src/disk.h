/* On-disk format
 * Copyright (C) 2012 Peter Todd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DISK_H
#define DISK_H

#include <stdint.h>

enum global_cipher_mode {
    CIPHER_MODE_AES
    // FIXME: support multiple modes AKA truecrypt. Also see Cryptographic
    // Engineering 3.5.6; AES is "close" to being broken.
    //
    // CIPHER_MODE_SERPENT,
    // CIPHER_MODE_TWOFISH,
};
extern enum global_cipher_mode global_cipher_mode;

enum global_hash_mode {
    HASH_MODE_SHA256
    // The hash function isn't as security critical, although on the other hand
    // what we need it most for, being statisticly identical to random data, is
    // an uncommon design requirement.
    //
    // HASH_MODE_SHA3 - One day
};
extern enum global_hash_mode global_hash_mode;

typedef char block_mac[32];
typedef char block_iv[16];
typedef char block_key[32];

#define BLOCK_FORMAT_VERSION 1

#define PAYLOAD_TYPE_DUMMY 1
#define PAYLOAD_TYPE_STREAM_HEADER 2
#define PAYLOAD_TYPE_CHUNK 3

struct stream_header_payload {
    uint64_t timestamp;

    char data[1];
} __attribute__ ((packed));

struct chunk_payload {
    uint64_t timestamp;
    uint64_t idx;
    uint32_t length;

    // Placeholder
    char data[1];
} __attribute__ ((packed));

struct block {
    block_iv iv;
    block_mac mac;

    uint8_t version;
    uint8_t type;

    uint16_t padding;

    union {
        struct chunk_payload chunk_payload;
        struct stream_header_payload stream_header_payload;
        char payload;
    };
} __attribute__ ((packed));

void encipher_block(struct block *block,size_t blocksize,block_key *key);

// True if the deciphered block is valid, false otherwise
bool decipher_block(struct block *block,size_t blocksize,block_key *key);

#define max_chunklength(block,blocksize) (blocksize - offsetof(struct block,chunk_payload.data))

#endif
