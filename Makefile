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
#CFLAGS += -D__IA64__
CFLAGS += -DUSE_MMAP
PREFIX  = /usr/local

all : dmidecode biosdecode ownership

ownership : ownership.o util.o
	$(CC) $^ -o $@

dmidecode : dmidecode.o util.o
	$(CC) $^ -o $@

biosdecode : biosdecode.o util.o
	$(CC) $^ -o $@

dmidecode.o : dmidecode.c version.h types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

biosdecode.o : biosdecode.c version.h types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

ownership.o : ownership.c version.h types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

util.o : util.c types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

install : dmidecode biosdecode
	install -m 755 dmidecode $(PREFIX)/sbin
	install -m 755 biosdecode $(PREFIX)/sbin
	install -m 755 ownership $(PREFIX)/sbin

uninstall :
	rm -f $(PREFIX)/sbin/dmidecode
	rm -f $(PREFIX)/sbin/biosdecode
	rm -f $(PREFIX)/sbin/ownership

clean :
	rm -f *.o dmidecode biosdecode ownership
