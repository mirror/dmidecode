#
#	DMI decode
#
#	(C) 2000-2002 Alan Cox <alan@redhat.com>
#
#	Licensed under the GNU Public license. If you want to use it in with
#	another license just ask.
#

CC      = gcc
CFLAGS  = -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
          -Wcast-align -Wwrite-strings -Wnested-externs -Winline -O2 \
          -pedantic -g
TARGET  = dmidecode
PREFIX  = /usr/local

all : $(TARGET)

$(TARGET) : dmidecode.c
	$(CC) $(CFLAGS) $< -o $@

install : $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/sbin

uninstall :
	rm -f $(PREFIX)/sbin/$(TARGET)

clean :
	rm -f $(TARGET) 
