bin_PROGRAMS = stegbak
stegbak_CLFAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)
stegbak_SOURCES = src/main.c src/common.c \
				  src/disk.c src/find.c src/hide.c \
				  src/passphrase.c
stegbak_LDADD = $(LIBOBJS) $(LIBGCRYPT_LIBS)
