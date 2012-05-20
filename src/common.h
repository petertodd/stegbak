/* Common functions and definitions.
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

#ifndef COMMON_H
#define COMMON_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <gcrypt.h>

extern char *program_name;

// Command line options
struct options {
    bool verbose;

    char *passphrase;
    unsigned long key_strengthening_iterations_exponent;

    // Shared between verify and find
    off_t location;

    size_t blocksize;

    time_t oldest_acceptable_timestamp;
};
extern struct options options;


// EXIT_FAILURE with a message
void verbose_exit(char *str,...);

// As above but using perror(str)
void perror_exit(char *str,...);

// As it says on the tin... secure memory isn't used.
char *buf_to_hex(void *buf,size_t len);

#endif
