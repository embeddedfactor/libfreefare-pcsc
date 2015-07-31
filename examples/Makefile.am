AM_CFLAGS = -I. -I$(top_srcdir)/libfreefare @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@
LDADD = $(top_builddir)/libfreefare/libfreefare.la
if HAVE_LIBNFC
AM_CFLAGS += @LIBNFC_CFLAGS@
LDADD += @LIBNFC_LIBS@
endif
if HAVE_PCSC
AM_CFLAGS += @PCSC_CFLAGS@
LDADD += @PCSC_LIBS@
endif

bin_PROGRAMS =
if HAVE_LIBNFC
bin_PROGRAMS += felica-lite-dump \
	       felica-read-ndef \
	       mifare-classic-format \
	       mifare-classic-write-ndef \
	       mifare-classic-read-ndef \
	       mifare-desfire-access \
	       mifare-desfire-create-ndef \
	       mifare-desfire-ev1-configure-ats \
	       mifare-desfire-ev1-configure-default-key \
	       mifare-desfire-ev1-configure-random-uid \
	       mifare-desfire-format \
	       mifare-desfire-info \
	       mifare-desfire-read-ndef \
	       mifare-desfire-write-ndef \
	       mifare-ultralight-info
endif

if HAVE_PCSC
bin_PROGRAMS += \
	       mifare-classic-format-pcsc \
	       mifare-classic-write-ndef-pcsc \
	       mifare-classic-read-ndef-pcsc \
	       mifare-desfire-access-pcsc \
	       mifare-desfire-create-ndef-pcsc \
	       mifare-desfire-ev1-configure-ats-pcsc \
	       mifare-desfire-ev1-configure-default-key-pcsc \
	       mifare-desfire-ev1-configure-random-uid-pcsc \
	       mifare-desfire-format-pcsc \
	       mifare-desfire-info-pcsc \
	       mifare-desfire-read-ndef-pcsc \
	       mifare-desfire-write-ndef-pcsc \
	       mifare-ultralight-info-pcsc
endif

if HAVE_LIBNFC
felica_lite_dump_SOURCES = felica-lite-dump.c
felica_lite_dump_LDADD = $(top_builddir)/libfreefare/libfreefare.la

felica_read_ndef_SOURCES = felica-read-ndef.c
felica_read_ndef_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_classic_format_SOURCES = mifare-classic-format.c
mifare_classic_read_ndef_SOURCES = mifare-classic-read-ndef.c
mifare_classic_write_ndef_SOURCES = mifare-classic-write-ndef.c
mifare_desfire_access_SOURCES = mifare-desfire-access.c
mifare_desfire_create_ndef_SOURCES = mifare-desfire-create-ndef.c
mifare_desfire_ev1_configure_ats_SOURCES = mifare-desfire-ev1-configure-ats.c
mifare_desfire_ev1_configure_default_key_SOURCES = mifare-desfire-ev1-configure-default-key.c
mifare_desfire_ev1_configure_random_uid_SOURCES = mifare-desfire-ev1-configure-random-uid.c
mifare_desfire_format_SOURCES = mifare-desfire-format.c
mifare_desfire_info_SOURCES = mifare-desfire-info.c
mifare_desfire_read_ndef_SOURCES = mifare-desfire-read-ndef.c
mifare_desfire_write_ndef_SOURCES = mifare-desfire-write-ndef.c
mifare_ultralight_info_SOURCES = mifare-ultralight-info.c
endif

if HAVE_PCSC
mifare_classic_format_pcsc_SOURCES = mifare-classic-format-pcsc.c
mifare_classic_read_ndef_pcsc_SOURCES = mifare-classic-read-ndef-pcsc.c
mifare_classic_write_ndef_pcsc_SOURCES = mifare-classic-write-ndef-pcsc.c
mifare_desfire_access_pcsc_SOURCES = mifare-desfire-access-pcsc.c
mifare_desfire_create_ndef_pcsc_SOURCES = mifare-desfire-create-ndef-pcsc.c
mifare_desfire_ev1_configure_ats_pcsc_SOURCES = mifare-desfire-ev1-configure-ats-pcsc.c
mifare_desfire_ev1_configure_default_key_pcsc_SOURCES = mifare-desfire-ev1-configure-default-key-pcsc.c
mifare_desfire_ev1_configure_random_uid_pcsc_SOURCES = mifare-desfire-ev1-configure-random-uid-pcsc.c
mifare_desfire_format_pcsc_SOURCES = mifare-desfire-format-pcsc.c
mifare_desfire_info_pcsc_SOURCES = mifare-desfire-info-pcsc.c
mifare_desfire_read_ndef_pcsc_SOURCES = mifare-desfire-read-ndef-pcsc.c
mifare_desfire_write_ndef_pcsc_SOURCES = mifare-desfire-write-ndef-pcsc.c
mifare_ultralight_info_pcsc_SOURCES = mifare-ultralight-info-pcsc.c
endif

CLEANFILES=	*.gcno
