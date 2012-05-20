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
#include <getopt.h>

#include "main.h"

#include "disk.h"
#include "find.h"
#include "hide.h"
#include "passphrase.h"

void usage(int status){
    if (status != EXIT_SUCCESS)
        fprintf (stderr, "Try `%s --help' for more information.\n", program_name);
    else {
        printf("\
Usage:\n\
  %s [options] hide <file>\n\
  %s [options] verify <partition>\n\
  %s [options] find <partition>\n\
\n\
Global options:\n\
  --help            display this help and exit\n\
  --version         display version and exit\n\
\n\
  -b, --blocksize=SIZE    specify filesystem blocksize\n\
  -p, --passphrase=PASS   specify passphrase\n\
  -v, --verbose           explain what is being done\n\
\n\
hide:\n\
  --no-delete         don't delete output file when finished\n\
\n\
find and verify:\n\
  -l, --location=OFFSET   look for header at given offset,\n\
                          if header not found, exit immediately\n\
", program_name,program_name,program_name);
    }
    exit(status);
}

void version_etc(){
    printf("\
%s v%s\n\
Copyright (C) 2012 Peter Todd\n\
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\
\n\
Bug reports to %s\n\
",PACKAGE_NAME,PACKAGE_VERSION,PACKAGE_BUGREPORT);
    exit(EXIT_SUCCESS);
}

int main(int argc,char **argv){
    static int print_version = 0;
    static int print_help = 0;

    // Save to be friendly later.
    program_name = strdup(argv[0]);


    // libgcrypt initialization
    //
    // Version check should be the very first call because it makes sure that
    // important subsystems are intialized.
    if (!gcry_check_version (GCRYPT_VERSION))
        verbose_exit("libgcrypt version mismatch");

    // We don't want to see any warnings, e.g. because we have not yet parsed
    // program options which might be used to suppress such warnings.
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    // Allocate a pool of 16k secure memory. This make the secure memory
    // available and also drops privileges where needed.
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    // It is now okay to let Libgcrypt complain when there was/is a problem
    // with the secure memory.
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    // Tell Libgcrypt that initialization has completed.
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);


    // Option parsing
    while (1){
        static struct option long_options[] = {
            {"blocksize", required_argument, NULL, 'b'},
            {"passphrase", required_argument,NULL,'p'},
            {"location", required_argument, NULL, 'l'},
            {"verbose", no_argument, NULL, 'v'},
            {"version", no_argument, &print_version, 1},
            {"help", no_argument, NULL, 'h'},
            {0,0,0,0}
        };

        int option_index = 0;
        int c = getopt_long(argc, argv, "b:l:p:vh", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 0:
                if (long_options[option_index].flag != 0)
                    break;
                printf("option %s", long_options[option_index].name);
                if (optarg)
                    printf(" with arg %s",optarg);
                printf("\n");
                break;
            case 'b':
                if (sscanf(optarg,"%ld",(long int *)&options.blocksize) != 1){
                    verbose_exit("Invalid blocksize %s",optarg);
                };
                if (options.blocksize < sizeof(struct block)){
                    verbose_exit("Blocksize too small. (got %ld, minimum %ld)",
                            options.blocksize,sizeof(struct block));
                }
                // FIXME: shouldn't be hardcoded
                if (options.blocksize % 16){
                    verbose_exit("Blocksize must be a multiple of the cipher block size, 16");
                }
                break;
            case 'l':
                if (sscanf(optarg,"%lx",(long int *)&options.location) != 1){
                    verbose_exit("Invalid location %s",optarg);
                };
                if (options.location < 0){
                    verbose_exit("Location must be a positive number");
                }
                break;
            case 'p':
                // If the user is specifying their passphrase on the command
                // line, there's no reason to worry about locking memory -
                // they're already screwed.
                options.passphrase = strdup(optarg);
                break;
            case 'v':
                options.verbose = true;
                break;
            case 'h':
                usage(EXIT_SUCCESS);
            case '?':
            default:
                usage(EXIT_FAILURE);
        }
    }
    if (print_version) version_etc();

    // Obtain passphrase, required for all operations.
    if (!options.passphrase){
        fprintf(stderr,"Enter passphrase: ");
        options.passphrase = obtain_passphrase_from_stream(stdin);

        char *passphrase2 = NULL;
        fprintf(stderr,"Re-enter passphrase: ");
        passphrase2 = obtain_passphrase_from_stream(stdin);

        if (strcmp(options.passphrase,passphrase2))
            verbose_exit("Passphrases don't match");
    }

    void *key;
    key = derive_key_from_passphrase(options.passphrase);
    //printf("%s\n",buf_to_hex(key,BASIC_KEY_LENGTH));

    if (argc <= optind){
        fprintf(stderr,"No command specified.\n");
        usage(EXIT_FAILURE);
    }

    if (!strcmp(argv[optind],"hide")){
        return hide(&options,key,argv[optind + 1],stdin);
    }
    else if (!strcmp(argv[optind],"verify")){
        //return verify_main(argc - optind,argv + optind);
    }
    else if (!strcmp(argv[optind],"find")){
        return find(&options,key,argv[optind +1],stdout);
    }
    else {
        fprintf(stderr,"Invalid command \"%s\" specified.\n",argv[optind]);
        usage(EXIT_FAILURE);
    }

    return 0;
}
