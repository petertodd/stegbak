AC_INIT([stegbak],[0.1],[pete@petertodd.org])

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.4.4

AC_DEFINE_UNQUOTED(NEED_LIBGCRYPT_VERSION, "$NEED_LIBGCRYPT_VERSION",
                    [Required version of Libgcrypt])

AC_LANG(C)
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_SYS_LARGEFILE

#
# Libgcrypt is our generic crypto library
#
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",
                          have_libgcrypt=yes,have_libgcrypt=no)

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
