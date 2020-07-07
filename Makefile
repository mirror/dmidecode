#
#   DMI Decode
#   BIOS Decode
#   VPD Decode
#
#   Copyright (C) 2000-2002 Alan Cox <alan@redhat.com>
#   Copyright (C) 2002-2020 Jean Delvare <jdelvare@suse.de>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#

CC     ?= gcc
# Base CFLAGS can be overridden by environment
CFLAGS ?= -O2
# When debugging, disable -O2 and enable -g
#CFLAGS ?= -g

CFLAGS += -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
          -Wcast-align -Wwrite-strings -Wmissing-prototypes -Winline -Wundef

# Let lseek and mmap support 64-bit wide offsets
CFLAGS += -D_FILE_OFFSET_BITS=64 -fPIC

#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND

# Pass linker flags here (can be set from environment too)
LDFLAGS ?=

DESTDIR =
prefix  = /usr
sbindir = $(prefix)/sbin
mandir  = $(prefix)/share/man
man8dir = $(mandir)/man8
docdir  = $(prefix)/share/doc/dmidecode
libdmidir = /libdmi

INSTALL         := install
INSTALL_DATA    := $(INSTALL) -m 644
INSTALL_DIR     := $(INSTALL) -m 755 -d
INSTALL_PROGRAM := $(INSTALL) -m 755
RM              := rm -f

# BSD make provides $MACHINE, but GNU make doesn't
MACHINE ?= $(shell uname -m 2>/dev/null)

# These programs are only useful on x86
LIB-FILES := libdmi.so libdmi.a
OBJS := libdmi.o dmiopt.o dmioem.o dmioutput.o util.o
LIB-HEADERS := libdmi.h types.h
PROGRAMS-i386 := biosdecode ownership vpddecode
PROGRAMS-i486 := $(PROGRAMS-i386)
PROGRAMS-i586 := $(PROGRAMS-i386)
PROGRAMS-i686 := $(PROGRAMS-i386)
PROGRAMS-x86_64 := biosdecode ownership vpddecode
PROGRAMS-amd64 := $(PROGRAMS-x86_64)

PROGRAMS := dmidecode $(PROGRAMS-$(MACHINE))

all : $(PROGRAMS) libdmi.so libdmi.a

#
# Programs
#

dmidecode : dmidecode.o libdmi.o dmiopt.o dmioem.o util.o dmioutput.o
	$(CC) $(LDFLAGS) dmidecode.o libdmi.o dmiopt.o dmioem.o util.o dmioutput.o -o $@

biosdecode : biosdecode.o util.o
	$(CC) $(LDFLAGS) biosdecode.o util.o -o $@

ownership : ownership.o util.o
	$(CC) $(LDFLAGS) ownership.o util.o -o $@

vpddecode : vpddecode.o vpdopt.o util.o
	$(CC) $(LDFLAGS) vpddecode.o vpdopt.o util.o -o $@

#
# Objects
#

libdmi.o : libdmi.c version.h types.h util.h config.h libdmi.h \
	      dmiopt.h dmioem.h dmioutput.h
	$(CC) $(CFLAGS) -c $< -o $@

dmidecode.o : main.c libdmi.c version.h types.h util.h config.h libdmi.h \
	      dmiopt.h dmioem.h
	$(CC) $(CFLAGS) -c $< -o $@

dmiopt.o : dmiopt.c config.h types.h util.h dmiopt.h
	$(CC) $(CFLAGS) -c $< -o $@

dmioem.o : dmioem.c types.h dmioem.h
	$(CC) $(CFLAGS) -c $< -o $@

dmioutput.o : dmioutput.c types.h dmioutput.h
	$(CC) $(CFLAGS) -c $< -o $@

biosdecode.o : biosdecode.c version.h types.h util.h config.h 
	$(CC) $(CFLAGS) -c $< -o $@

ownership.o : ownership.c version.h types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

vpddecode.o : vpddecode.c version.h types.h util.h config.h vpdopt.h
	$(CC) $(CFLAGS) -c $< -o $@

vpdopt.o : vpdopt.c config.h util.h vpdopt.h
	$(CC) $(CFLAGS) -c $< -o $@

util.o : util.c types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

libdmi.so : $(OBJS)
	$(CC) $(CFLAGS) -shared $^ -o $@

libdmi.a : $(OBJS)
	ar rcs $@ $^

#
# Commands
#

strip : $(PROGRAMS)
	strip $(PROGRAMS)

install : install-bin install-man install-doc install-lib

uninstall : uninstall-bin uninstall-man uninstall-doc uninstall-lib

install-bin : $(PROGRAMS)
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	for program in $(PROGRAMS) ; do \
	$(INSTALL_PROGRAM) $$program $(DESTDIR)$(sbindir) ; done

uninstall-bin :
	for program in $(PROGRAMS) ; do \
	$(RM) $(DESTDIR)$(sbindir)/$$program ; done

install-lib:
	$(INSTALL_DIR) $(DESTDIR)$(prefix)/lib$(libdmidir)
	$(INSTALL_DIR) $(DESTDIR)$(prefix)/include$(libdmidir)
	for program in $(LIB-FILES) ; do \
	$(INSTALL_PROGRAM) $$program $(DESTDIR)$(prefix)/lib$(libdmidir)/ ; done
	for program in $(LIB-HEADERS) ; do \
	$(INSTALL_PROGRAM) $$program $(DESTDIR)$(prefix)/include$(libdmidir)/ ; done

uninstall-lib:
	for program in $(LIB-FILES) ; do \
	$(RM) $(DESTDIR)$(prefix)/lib$(libdmidir)/$$program ; done
	for program in $(LIB-HEADERS) ; do \
	$(RM) $(DESTDIR)$(prefix)/include$(libdmidir)/$$program ; done

install-man :
	$(INSTALL_DIR) $(DESTDIR)$(man8dir)
	for program in $(PROGRAMS) ; do \
	$(INSTALL_DATA) man/$$program.8 $(DESTDIR)$(man8dir) ; done

uninstall-man :
	for program in $(PROGRAMS) ; do \
	$(RM) $(DESTDIR)$(man8dir)/$$program.8 ; done

install-doc :
	$(INSTALL_DIR) $(DESTDIR)$(docdir)
	$(INSTALL_DATA) README $(DESTDIR)$(docdir)
	$(INSTALL_DATA) NEWS $(DESTDIR)$(docdir)
	$(INSTALL_DATA) AUTHORS $(DESTDIR)$(docdir)

uninstall-doc :
	$(RM) -r $(DESTDIR)$(docdir)

clean :
	$(RM) *.a *.so *.o $(PROGRAMS) core
