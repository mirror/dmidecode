#
#	DMI Decode
#	BIOS Decode
#
#	(C) 2000-2002 Alan Cox <alan@redhat.com>
#	(C) 2002-2003 Jean Delvare <khali@linux-fr.org>
#
#	Licensed under the GNU Public license. If you want to use it in with
#	another license just ask.
#

CC      = gcc
CFLAGS  = -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
          -Wcast-align -Wwrite-strings -O2 -pedantic -g
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND
#CFLAGS += -DTABLE_LITTLEENDIAN
PREFIX  = /usr/local

all : dmidecode biosdecode

dmidecode : dmidecode.c version.h
	$(CC) $(CFLAGS) $< -o $@

biosdecode : biosdecode.c version.h
	$(CC) $(CFLAGS) $< -o $@

install : dmidecode biosdecode
	install -m 755 dmidecode $(PREFIX)/sbin
	install -m 755 biosdecode $(PREFIX)/sbin

uninstall :
	rm -f $(PREFIX)/sbin/dmidecode
	rm -f $(PREFIX)/sbin/biosdecode

clean :
	rm -f dmidecode biosdecode
