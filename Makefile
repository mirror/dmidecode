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
          -Wcast-align -Wwrite-strings -pedantic
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND
#CFLAGS += -DTABLE_LITTLEENDIAN
#CFLAGS += -D__IA64__
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

uninstall :
	rm -f $(PREFIX)/sbin/dmidecode
	rm -f $(PREFIX)/sbin/biosdecode
	rm -f $(PREFIX)/sbin/ownership
	rm -f $(PREFIX)/sbin/vpddecode

clean :
	rm -f *.o dmidecode biosdecode ownership vpddecode
