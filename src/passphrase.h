/* Passphrase handling and key derivation
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

#ifndef PASSPHRASE_H
#define PASSPHRASE_H

#include "disk.h"

#define MAX_PASSPHRASE_LENGTH 1024
char *obtain_passphrase_from_stream(FILE *stream);

// Turn a passphrase into a strong key by repeated hashing.
//
// Why hashing rather than an existing well-known key derivation function? We
// want the algorithm to be simple enough to be implemented in an hour or two
// should the user need their data, but don't have a copy of stegbak. All the
// well-known KDF's are complex, especially memory hard ones.
block_key *derive_key_from_passphrase(const char *passphrase,uint64_t iterations);

#endif
