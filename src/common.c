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

#include <sys/mman.h>

#include <stdarg.h>

char *program_name = NULL;

struct options options = {
    .verbose = false,

    .passphrase = NULL,

    .location = -1,

    .blocksize = 4096
};

void perror_exit(char *str,...){
    char *msg;
    va_list ap;
    va_start(ap,str);
    vasprintf(&msg,str,ap);

    perror(msg);
    exit(EXIT_FAILURE);
}

void verbose_exit(char *str,...){
    char *msg;
    va_list ap;
    va_start(ap,str);
    vasprintf(&msg,str,ap);

    fputs(msg,stderr);
    fputs("\n",stderr);
    exit(EXIT_FAILURE);
}

char *buf_to_hex(void *buf,size_t len){
    int i;
    char *r = malloc((len * 2) + 1);
    for (i = 0; i < len; i++){
        unsigned char w = ((unsigned char *)buf)[i];
        // lower nibble
        if ((w & 0x0f) < 10){
            r[i*2 + 1] = '0' + (w & 0x0f);
        } else {
            r[i*2 + 1] = 'a' + (w & 0x0f) - 10;
        };
        // upper nibble
        w >>= 4;
        if ((w & 0x0f) < 10){
            r[i*2 + 0] = '0' + (w & 0x0f);
        } else {
            r[i*2 + 0] = 'a' + (w & 0x0f) - 10;
        };
    }
    r[i*2] = 0;
    return r;
}
