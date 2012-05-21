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
#include <time.h>

int hide(struct options *options,block_key *key,char *output_file,FILE *input){
    FILE *output = NULL;
    struct block *block;
    uint64_t stream_timestamp;
    gcry_md_hd_t stream_hash_hd;

    // Setup for the full stream hash
    assert(!gcry_md_open(&stream_hash_hd,GCRY_MD_MD5,0));

    if (options->verbose) {
        if (output_file){
            fprintf(stderr,"Hiding data in file '%s'\n",output_file);
        } else {
            fprintf(stderr,"Hiding data in standard output.\n");
        }
    }

    // Setup the output file descriptor
    if (!output_file){
        output = stdout;
    } else {
        struct stat buf;
        // Check if the output file already exists
        if (!stat(output_file,&buf))
           verbose_exit("Output '%s' already exists",output_file);
        if (!(output = fopen(output_file,"w")))
            perror_exit("Error while creating output file");
    }

    // Create the header
    stream_timestamp = time(NULL);

    block = calloc(1,options->blocksize);
    block->version = BLOCK_FORMAT_VERSION;
    block->type = PAYLOAD_TYPE_STREAM_HEADER;
    block->padding = 0;
    block->stream_header_payload.timestamp = stream_timestamp;

    encipher_block(block,options->blocksize,key);

    if (fwrite(block,options->blocksize,1,output) != 1){
        perror_exit("Failed while writing stream header block to output");
    }
    free(block);


    // Encipher data
    uint64_t idx = 0;
    bool have_output_last_block = false;
    while (!feof(input) && !have_output_last_block){
        // If the input data happens to be an exact multiple of the maximum
        // chunk size we still need to output one last chunk with a length of 0
        // to signal the end of the stream.
        //
        // If the input data isn't an exact multiple this code will emit a
        // harmless additional block that will be ignored.
        if (feof(input))
            have_output_last_block = true;

        struct block *block = calloc(1,options->blocksize);

        block->version = BLOCK_FORMAT_VERSION;
        block->type = PAYLOAD_TYPE_CHUNK;
        block->padding = 0;
        int l = fread(block->chunk_payload.data,1,max_chunklength(block,options->blocksize),input);

        // Add the new data to the stream hash
        gcry_md_write(stream_hash_hd,block->chunk_payload.data,l);

        block->chunk_payload.timestamp = stream_timestamp;

        block->chunk_payload.length = l;
        block->chunk_payload.idx = idx;
        idx += l;

        encipher_block(block,options->blocksize,key);

        if (fwrite(block,options->blocksize,1,output) != 1){
            perror_exit("Failed while writing chunk block to output");
        }

        free(block);
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

    // Sync-to-disk and delete the output.
    if (output_file){
        if (options->verbose) fprintf(stderr,"Syncing\n");
        if (fsync(fileno(output)))
            perror_exit("Error while syncing output to disk");
        if (!options->no_delete){
            if (options->verbose) fprintf(stderr,"Unlinking\n");
            if (unlink(output_file))
                perror_exit("Couldn't remove output file");
        }
    }
    return 0;
}
