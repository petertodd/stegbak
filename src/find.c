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
#include <errno.h>

int find(struct options *options,block_key *key,char *container_path,FILE *output){
    FILE *input;
    struct block *header_block = calloc(1,options->blocksize);
    struct block *block = calloc(1,options->blocksize);
    uint64_t stream_timestamp;
    off_t pos;
    off_t pos_of_last_found_block;
    uint64_t next_block_idx;
    gcry_md_hd_t stream_hash_hd;

    // Setup for the full stream hash
    assert(!gcry_md_open(&stream_hash_hd,GCRY_MD_MD5,0));

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
    pos = 0;

    // Seek if required
    if (options->seek > 0){
        if (fseeko(input,options->seek,SEEK_SET)){
            if (errno != ESPIPE)
                perror_exit("Error! Couldn't seek as requested.");
            // Must be a non-seekable pipe, consume data until we're there
            while (pos < options->seek){
                void *buf = malloc(options->blocksize);
                size_t l = fread(buf,
                                 min(options->blocksize,options->seek - pos),1,
                                 input);
                pos += min(options->blocksize,options->seek - pos);
                if (l != 1){
                    perror_exit("Error while seeking in stream");
                }
            }
        }
        pos = options->seek;
    }
    while (1){
        size_t l = fread(header_block,options->blocksize,1,input);
        if (l != 1){
            verbose_exit("Couldn't find a valid header");
        }

        if (decipher_block(header_block,options->blocksize,key)){
            if (header_block->version == BLOCK_FORMAT_VERSION
                && header_block->type == PAYLOAD_TYPE_STREAM_HEADER){
                if (header_block->stream_header_payload.timestamp
                        > options->newer_than){
                    stream_timestamp = header_block->stream_header_payload.timestamp;
                    if (options->verbose){
                        char s[256];
                        time_to_human_readable(stream_timestamp,s,sizeof(s));
                        fprintf(stderr,"Found header with timestamp %ld (%s) at 0x%lx\n",
                                stream_timestamp,s,pos);
                    }
                    break;
                }
            }
        }
        pos += options->blocksize;
    }

    // Find the data
    pos_of_last_found_block = pos - options->blocksize;
    next_block_idx = 0;
    while (1){
        if (pos == pos_of_last_found_block){
            verbose_exit("Error! Couldn't find all data in input;"\
                   " wrapped around at position 0x%lx looking for block idx 0x%lx",
                   pos,next_block_idx);
        }
        size_t l = fread(block,options->blocksize,1,input);
        if (l != 1){
            // On end-of-file, wrap to the beginning
            if (feof(input)){
                clearerr(input);
                if (fseeko(input,0,SEEK_SET)){
                    if (errno == ESPIPE){
                        // Couldn't seek because our input isn't seekable. (fifo etc.)
                        verbose_exit("Error! Couldn't find all data in input;"\
                               " EOF at offset 0x%lx",pos);
                    }
                } else {
                    // Seek successful
                    pos = 0;
                    continue;
                }
            }
            // Some other error, or fseeko() failed due to a reason other than ESPIPE
            perror_exit("Error while trying to find data");
            break;
        }

        if (decipher_block(block,options->blocksize,key)){
            if (block->version == BLOCK_FORMAT_VERSION){
                if (block->type == PAYLOAD_TYPE_CHUNK
                    && block->chunk_payload.timestamp == stream_timestamp
                    && block->chunk_payload.idx == next_block_idx){
                    next_block_idx += block->chunk_payload.length;
                    l = fwrite(block->chunk_payload.data,block->chunk_payload.length,1,output);
                    if (l != 1){
                        perror_exit("Failed while writing found data to output");
                    }

                    // Add the new data to the stream hash
                    gcry_md_write(stream_hash_hd,
                            block->chunk_payload.data,block->chunk_payload.length);

                    // Detect end of stream.
                    if (block->chunk_payload.length != max_chunklength(block,options->blocksize))
                        break;
                }
                // Detect header blocks with timestamps newer than the stream
                // we are currently working on.
                else if (block->type == PAYLOAD_TYPE_CHUNK
                        && block->chunk_payload.timestamp > stream_timestamp){
                    char s[256],s2[256];
                    time_to_human_readable(block->chunk_payload.timestamp,s,sizeof(s));
                    fprintf(stderr,\
"Error! Found a newer header, timestamp %ld (%s) at position 0x%lx\n"\
"You can restart using this header with the options --seek=0x%lx --newer-than=%ld\n",
                        block->chunk_payload.timestamp,s,pos,
                        pos,block->chunk_payload.timestamp-1);
                    exit(EXIT_FAILURE);
                }
            }
        }
        pos += options->blocksize;
    }

    char str_stream_timestamp[256];
    time_to_human_readable(stream_timestamp,
            str_stream_timestamp,sizeof(str_stream_timestamp));
    fprintf(stderr,
"Done! Timestamp: %ld - %s\n"\
"      MD5: %s\n",
            stream_timestamp,str_stream_timestamp,
            buf_to_hex(gcry_md_read(stream_hash_hd,0),
                       gcry_md_get_algo_dlen(GCRY_MD_MD5)));


    free(block);
    return 0;
}
