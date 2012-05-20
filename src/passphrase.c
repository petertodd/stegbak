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
#include "passphrase.h"

char *obtain_passphrase_from_stream(FILE *stream){
    char *r = gcry_malloc_secure(MAX_PASSPHRASE_LENGTH + 1);

    // Getting the passphrase a character at a time is probably safe as only a
    // single character should end up on the stack, overwritten by the next one
    // each time. Still...
    //
    // FIXME: look into replacing this with pinentry or something similar
    int c;
    int i = 0;
    while (1) {
        c = fgetc(stream);
        if (c == EOF || c == '\n')
            break;
        if (i >= MAX_PASSPHRASE_LENGTH)
            verbose_exit("Passphrase too long; maximum is %d characters",MAX_PASSPHRASE_LENGTH);
        r[i] = (char)c;
        i++;
    }
    r[i] = 0;

    return r;
}

void *derive_key_from_passphrase(char *passphrase){
    void *key = gcry_malloc_secure(BASIC_KEY_LENGTH);
    gcry_md_hash_buffer(GCRY_MD_SHA256,key,passphrase,strlen(passphrase));

    return key;
}
