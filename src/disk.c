/* Copyright (C) 2012 Peter Todd
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"

#include <endian.h>

#include "disk.h"

enum global_cipher_mode global_cipher_mode = CIPHER_MODE_AES;
enum global_hash_mode global_hash_mode = HASH_MODE_SHA256;

// FIXME: shouldn't be using asserts to check for gcry errors

void compute_block_mac(struct block *block,size_t blocksize,block_key *key,block_mac mac){
    gcry_md_hd_t hd;
    assert(global_hash_mode == HASH_MODE_SHA256);

    assert(!gcry_md_open(&hd,GCRY_MD_SHA256,GCRY_MD_FLAG_SECURE|GCRY_MD_FLAG_HMAC));

    assert(!gcry_md_setkey(hd,key,sizeof(block_key)));

    // IV first
    gcry_md_write(hd,block->iv,sizeof(block_iv));

    // Skip the mac and hash everything after
    gcry_md_write(hd,&block->version,blocksize - offsetof(struct block,version));

    // The buffer that gcry_md_read() returns is valid only for the lifetime of
    // the handle.
    memcpy(mac,gcry_md_read(hd,GCRY_MD_SHA256),sizeof(block_mac));

    gcry_md_close(hd);
}

void convert_block_to_disk_endian(struct block *block){
    switch (block->type){
        case PAYLOAD_TYPE_DUMMY:
            break;
        case PAYLOAD_TYPE_STREAM_HEADER:
            block->stream_header_payload.timestamp = htobe64(block->stream_header_payload.timestamp);
            break;
        case PAYLOAD_TYPE_CHUNK:
            block->chunk_payload.timestamp = htobe64(block->chunk_payload.timestamp);
            block->chunk_payload.idx = htobe64(block->chunk_payload.idx);
            block->chunk_payload.length = htobe32(block->chunk_payload.length);
            break;
        default:
            // Shouldn't happen...
            assert(0);
    }
}

void convert_block_to_host_endian(struct block *block){
    switch (block->type){
        case PAYLOAD_TYPE_DUMMY:
            break;
        case PAYLOAD_TYPE_STREAM_HEADER:
            block->stream_header_payload.timestamp = be64toh(block->stream_header_payload.timestamp);
            break;
        case PAYLOAD_TYPE_CHUNK:
            block->chunk_payload.timestamp = be64toh(block->chunk_payload.timestamp);
            block->chunk_payload.idx = be64toh(block->chunk_payload.idx);
            block->chunk_payload.length = be32toh(block->chunk_payload.length);
            break;
        default:
            // Shouldn't happen...
            assert(0);
    }
}

void encipher_block(struct block *block,size_t blocksize,block_key *key){
    gcry_cipher_hd_t hd;
    gcry_error_t err;

    assert(blocksize >= sizeof(struct block));

    convert_block_to_disk_endian(block);

    gcry_create_nonce(block->iv,sizeof(block->iv));
    compute_block_mac(block,blocksize,key,block->mac);

    assert(global_cipher_mode == CIPHER_MODE_AES);
    assert(!gcry_cipher_open(&hd,GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CBC,GCRY_CIPHER_SECURE));
    assert(!gcry_cipher_setiv(hd,block->iv,sizeof(block_iv)));
    assert(!gcry_cipher_setkey(hd,key,sizeof(block_key)));

    assert(!gcry_cipher_encrypt(hd,block->mac,blocksize - offsetof(struct block,mac),NULL,0));

    gcry_cipher_close(hd);
}

bool decipher_block(struct block *block,size_t blocksize,block_key *key){
    gcry_cipher_hd_t hd;
    block_mac calculated_mac;

    assert(global_cipher_mode == CIPHER_MODE_AES);
    assert(!gcry_cipher_open(&hd,GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CBC,GCRY_CIPHER_SECURE));
    assert(!gcry_cipher_setiv(hd,block->iv,sizeof(block_iv)));
    assert(!gcry_cipher_setkey(hd,key,sizeof(block_key)));

    assert(!gcry_cipher_decrypt(hd,block->mac,blocksize - offsetof(struct block,mac),NULL,0));

    compute_block_mac(block,blocksize,key,calculated_mac);

    gcry_cipher_close(hd);

    if (!memcmp(block->mac,calculated_mac,sizeof(block_mac))){
        convert_block_to_host_endian(block);
        return true;
    } else {
        return false;
    }
}
