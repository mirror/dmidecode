#
#	DMI Decode
#	BIOS Decode
#
#	(C) 2000-2002 Alan Cox <alan@redhat.com>
#	(C) 2002-2004 Jean Delvare <khali@linux-fr.org>
#
#	Licensed under the GNU Public License.
#

CC      = gcc
CFLAGS  = -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
          -Wcast-align -Wwrite-strings -pedantic
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND
#CFLAGS += -DTABLE_LITTLEENDIAN
CFLAGS += -DUSE_MMAP

# When debugging, disable -O2 and enable -g.
CFLAGS += -O2
#CFLAGS += -g

PREFIX  = /usr/local

all : dmidecode biosdecode ownership vpddecode

#
# Programs
#

dmidecode : dmidecode.o util.o
	$(CC) dmidecode.o util.o -o $@

biosdecode : biosdecode.o util.o
	$(CC) biosdecode.o util.o -o $@

ownership : ownership.o util.o
	$(CC) ownership.o util.o -o $@

vpddecode : vpddecode.o util.o
	$(CC) vpddecode.o util.o -o $@

#
# Objects
#

dmidecode.o : dmidecode.c version.h types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

biosdecode.o : biosdecode.c version.h types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

ownership.o : ownership.c types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

vpddecode.o : vpddecode.c version.h types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

util.o : util.c types.h util.h
	$(CC) $(CFLAGS) -c $< -o $@

#
# Commands
#

strip : all
	strip dmidecode biosdecode ownership vpddecode

install : all
	install -m 755 dmidecode $(PREFIX)/sbin
	install -m 755 biosdecode $(PREFIX)/sbin
	install -m 755 ownership $(PREFIX)/sbin
	install -m 755 vpddecode $(PREFIX)/sbin
	install -m 644 man/dmidecode.8 $(PREFIX)/man/man8
	install -m 644 man/biosdecode.8 $(PREFIX)/man/man8
	install -m 644 man/ownership.8 $(PREFIX)/man/man8
	install -m 644 man/vpddecode.8 $(PREFIX)/man/man8

uninstall :
	rm -f $(PREFIX)/sbin/dmidecode $(PREFIX)/man/man8/dmidecode.8
	rm -f $(PREFIX)/sbin/biosdecode $(PREFIX)/man/man8/biosdecode.8
	rm -f $(PREFIX)/sbin/ownership $(PREFIX)/man/man8/ownership.8
	rm -f $(PREFIX)/sbin/vpddecode $(PREFIX)/man/man8/vpddecode.8

clean :
	rm -f *.o dmidecode biosdecode ownership vpddecode core
