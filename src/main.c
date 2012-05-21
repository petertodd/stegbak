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
                          (default: %ld)\n\
  -i, --iterations=N      strengthen passphrase by 10^N iterations\n\
                          (default: %ld)\n\
  -p, --passphrase=PASS   specify passphrase\n\
  -v, --verbose           explain what is being done\n\
\n\
hide:\n\
  --no-delete             don't delete output file when finished\n\
\n\
find:\n\
  -s, --seek=OFFSET       seek to OFFSET before looking for stream header\n\
  -n, --newer-than=SECS   ignore streams with timestamps older than SECS\n\
                          seconds since the Epoch\n\
", program_name,program_name,program_name,
            options.blocksize,
            options.key_strengthening_iterations_exponent);
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
    static int set_no_delete = 0;

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
            {"iterations", required_argument,NULL,'i'},
            {"passphrase", required_argument,NULL,'p'},
            {"newer-than", required_argument,NULL,'n'},
            {"no-delete", no_argument, &set_no_delete, 1},
            {"seek", required_argument, NULL, 's'},
            {"verbose", no_argument, NULL, 'v'},
            {"version", no_argument, &print_version, 1},
            {"help", no_argument, NULL, 'h'},
            {0,0,0,0}
        };

        int option_index = 0;
        int c = getopt_long(argc, argv, "b:i:l:n:p:vh", long_options, &option_index);

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
            case 'i':
                if (sscanf(optarg,"%lx",
                            (long int *)&options.key_strengthening_iterations_exponent) != 1){
                    verbose_exit("Invalid iterations exponent %s",optarg);
                };
                if (options.key_strengthening_iterations_exponent < 0){
                    verbose_exit("Iterations exponent must be a positive number");
                }
                break;
            case 's':
                if (sscanf(optarg,"%lx",(long int *)&options.seek) != 1){
                    verbose_exit("Invalid seek offset %s",optarg);
                };
                if (options.seek < 0){
                    verbose_exit("Seek offset must be a positive number");
                }
                break;
            case 'n':
                if (sscanf(optarg,"%ld",(long int *)&options.newer_than) != 1){
                    verbose_exit("Invalid argument to --newer-than %s",optarg);
                };
                if (options.newer_than < 0){
                    verbose_exit("--newer-than argument must be a positive number");
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
    if (set_no_delete) options.no_delete = true;

    // Obtain passphrase, required for all operations.
    if (!options.passphrase){
        fprintf(stderr,"Enter passphrase: ");
        options.passphrase = obtain_passphrase_from_stream(stdin);

        char *passphrase2 = NULL;
        fprintf(stderr,"Re-enter passphrase: ");
        passphrase2 = obtain_passphrase_from_stream(stdin);

        if (strcmp(options.passphrase,passphrase2))
            verbose_exit("Passphrases don't match");
        free(passphrase2);
    }

    block_key *key;
    uint64_t iterations = 1;
    unsigned long i;
    for (i = 0; i < options.key_strengthening_iterations_exponent; i++){
        // I can't believe I have to implement exponentiation by repeated
        // multiplication...
        iterations *= 10;
    }
    key = derive_key_from_passphrase(options.passphrase,iterations);

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
