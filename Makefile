#
#	DMI Decode
#	BIOS Decode
#
#	(C) 2000-2002 Alan Cox <alan@redhat.com>
#	(C) 2002-2005 Jean Delvare <khali@linux-fr.org>
#
#	Licensed under the GNU Public License.
#

CC      = gcc
CFLAGS  = -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
          -Wcast-align -Wwrite-strings -Wmissing-prototypes -Winline
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND

# When debugging, disable -O2 and enable -g.
CFLAGS += -O2
#CFLAGS += -g

# Pass linker flags here
LDFLAGS =

DESTDIR =
prefix  = /usr/local
sbindir = $(prefix)/sbin
mandir  = $(prefix)/man
man8dir = $(mandir)/man8

all : dmidecode biosdecode ownership vpddecode

#
# Programs
#

dmidecode : dmidecode.o util.o
	$(CC) $(LDFLAGS) dmidecode.o util.o -o $@

biosdecode : biosdecode.o util.o
	$(CC) $(LDFLAGS) biosdecode.o util.o -o $@

ownership : ownership.o util.o
	$(CC) $(LDFLAGS) ownership.o util.o -o $@

vpddecode : vpddecode.o util.o
	$(CC) $(LDFLAGS) vpddecode.o util.o -o $@

#
# Objects
#

dmidecode.o : dmidecode.c version.h types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

biosdecode.o : biosdecode.c version.h types.h util.h config.h 
	$(CC) $(CFLAGS) -c $< -o $@

ownership.o : ownership.c version.h types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

vpddecode.o : vpddecode.c version.h types.h util.h config.h 
	$(CC) $(CFLAGS) -c $< -o $@

util.o : util.c types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

#
# Commands
#

strip : all
	strip dmidecode biosdecode ownership vpddecode

install : all
	install -d $(DESTDIR)$(sbindir) $(DESTDIR)$(man8dir)
	install -m 755 dmidecode $(DESTDIR)$(sbindir)
	install -m 755 biosdecode $(DESTDIR)$(sbindir)
	install -m 755 ownership $(DESTDIR)$(sbindir)
	install -m 755 vpddecode $(DESTDIR)$(sbindir)
	install -m 644 man/dmidecode.8 $(DESTDIR)$(man8dir)
	install -m 644 man/biosdecode.8 $(DESTDIR)$(man8dir)
	install -m 644 man/ownership.8 $(DESTDIR)$(man8dir)
	install -m 644 man/vpddecode.8 $(DESTDIR)$(man8dir)

uninstall :
	rm -f $(DESTDIR)$(sbindir)/dmidecode $(DESTDIR)$(man8dir)/dmidecode.8
	rm -f $(DESTDIR)$(sbindir)/biosdecode $(DESTDIR)$(man8dir)/biosdecode.8
	rm -f $(DESTDIR)$(sbindir)/ownership $(DESTDIR)$(man8dir)/ownership.8
	rm -f $(DESTDIR)$(sbindir)/vpddecode $(DESTDIR)$(man8dir)/vpddecode.8

clean :
	rm -f *.o dmidecode biosdecode ownership vpddecode core
