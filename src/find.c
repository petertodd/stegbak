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
#include "disk.h"
#include "hide.h"

#include <sys/stat.h>

int find(struct options *options,block_key *key,char *container_path,FILE *output){
    FILE *input;
    struct block *header_block = calloc(1,options->blocksize);
    struct block *block = calloc(1,options->blocksize);
    uint64_t stream_timestamp;
    size_t idx;

    if (options->verbose) {
        if (container_path){
            fprintf(stderr,"Finding data in '%s'\n",container_path);
        } else {
            fprintf(stderr,"Finding data in standard input.\n");
        }
    }

    // Setup the container file descriptor
    if (!container_path){
        input = stdin;
    } else {
        input = fopen(container_path,"r");
        if (!input)
            perror_exit("Couldn't open '%s'",container_path);
    }

    // Find a sufficiently recent header
    stream_timestamp = time(NULL);
    idx = 0;
    while (1){
        size_t l = fread(header_block,options->blocksize,1,input);
        if (l != 1){
            verbose_exit("Couldn't find a valid header");
        }
        idx += options->blocksize;

        if (decipher_block(header_block,options->blocksize,key)){
            if (header_block->version == BLOCK_FORMAT_VERSION
                && header_block->type == PAYLOAD_TYPE_STREAM_HEADER){
                if (header_block->stream_header_payload.timestamp
                        >= options->oldest_acceptable_timestamp){
                    stream_timestamp = header_block->stream_header_payload.timestamp;
                    if (options->verbose){
                        fprintf(stderr,"Found header with timestamp %ld\n",stream_timestamp);
                    }
                    break;
                }
            }
        }
    }

    // Find the data
    idx = 0;
    while (1){
        size_t l = fread(block,options->blocksize,1,input);
        if (l != 1){
            break;
        }

        if (decipher_block(block,options->blocksize,key)){
            if (block->version == BLOCK_FORMAT_VERSION
                && block->type == PAYLOAD_TYPE_CHUNK
                && block->chunk_payload.timestamp == stream_timestamp
                && block->chunk_payload.idx == idx){
                idx += options->blocksize;
                l = fwrite(block->chunk_payload.data,block->chunk_payload.length,1,output);
                if (l != 1){
                    perror_exit("Failed while writing found data to output");
                }
            }
        }
    }

    free(block);
    return 0;
}
