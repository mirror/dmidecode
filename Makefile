#
#	DMI Decode
#	BIOS Decode
#
#	(C) 2000-2002 Alan Cox <alan@redhat.com>
#	(C) 2002-2007 Jean Delvare <khali@linux-fr.org>
#
#	Licensed under the GNU Public License.
#

CC      = gcc
CFLAGS  = -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
          -Wcast-align -Wwrite-strings -Wmissing-prototypes -Winline -Wundef
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
mandir  = $(prefix)/share/man
man8dir = $(mandir)/man8
docdir  = $(prefix)/share/doc/dmidecode

INSTALL         := install
INSTALL_DATA    := $(INSTALL) -m 644
INSTALL_DIR     := $(INSTALL) -m 755 -d
INSTALL_PROGRAM := $(INSTALL) -m 755
RM              := rm -f

all : dmidecode biosdecode ownership vpddecode

#
# Programs
#

dmidecode : dmidecode.o dmiopt.o dmioem.o util.o
	$(CC) $(LDFLAGS) dmidecode.o dmiopt.o dmioem.o util.o -o $@

biosdecode : biosdecode.o util.o
	$(CC) $(LDFLAGS) biosdecode.o util.o -o $@

ownership : ownership.o util.o
	$(CC) $(LDFLAGS) ownership.o util.o -o $@

vpddecode : vpddecode.o vpdopt.o util.o
	$(CC) $(LDFLAGS) vpddecode.o vpdopt.o util.o -o $@

#
# Objects
#

dmidecode.o : dmidecode.c version.h types.h util.h config.h dmidecode.h \
	      dmiopt.h dmioem.h
	$(CC) $(CFLAGS) -c $< -o $@

dmiopt.o : dmiopt.c config.h types.h dmidecode.h dmiopt.h
	$(CC) $(CFLAGS) -c $< -o $@

dmioem.o : dmioem.c types.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c $< -o $@

biosdecode.o : biosdecode.c version.h types.h util.h config.h 
	$(CC) $(CFLAGS) -c $< -o $@

ownership.o : ownership.c version.h types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

vpddecode.o : vpddecode.c version.h types.h util.h config.h vpdopt.h
	$(CC) $(CFLAGS) -c $< -o $@

vpdopt.o : vpdopt.c config.h vpdopt.h
	$(CC) $(CFLAGS) -c $< -o $@

util.o : util.c types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

#
# Commands
#

strip : all
	strip dmidecode biosdecode ownership vpddecode

install : install-bin install-man install-doc

uninstall : uninstall-bin uninstall-man uninstall-doc

install-bin : all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROGRAM) dmidecode $(DESTDIR)$(sbindir)
	$(INSTALL_PROGRAM) biosdecode $(DESTDIR)$(sbindir)
	$(INSTALL_PROGRAM) ownership $(DESTDIR)$(sbindir)
	$(INSTALL_PROGRAM) vpddecode $(DESTDIR)$(sbindir)

uninstall-bin :
	$(RM) $(DESTDIR)$(sbindir)/dmidecode
	$(RM) $(DESTDIR)$(sbindir)/biosdecode
	$(RM) $(DESTDIR)$(sbindir)/ownership
	$(RM) $(DESTDIR)$(sbindir)/vpddecode

install-man :
	$(INSTALL_DIR) $(DESTDIR)$(man8dir)
	$(INSTALL_DATA) man/dmidecode.8 $(DESTDIR)$(man8dir)
	$(INSTALL_DATA) man/biosdecode.8 $(DESTDIR)$(man8dir)
	$(INSTALL_DATA) man/ownership.8 $(DESTDIR)$(man8dir)
	$(INSTALL_DATA) man/vpddecode.8 $(DESTDIR)$(man8dir)

uninstall-man :
	$(RM) $(DESTDIR)$(man8dir)/dmidecode.8
	$(RM) $(DESTDIR)$(man8dir)/biosdecode.8
	$(RM) $(DESTDIR)$(man8dir)/ownership.8
	$(RM) $(DESTDIR)$(man8dir)/vpddecode.8

install-doc :
	$(INSTALL_DIR) $(DESTDIR)$(docdir)
	$(INSTALL_DATA) README $(DESTDIR)$(docdir)
	$(INSTALL_DATA) CHANGELOG $(DESTDIR)$(docdir)
	$(INSTALL_DATA) AUTHORS $(DESTDIR)$(docdir)

uninstall-doc :
	$(RM) -r $(DESTDIR)$(docdir)

clean :
	$(RM) *.o dmidecode biosdecode ownership vpddecode core
