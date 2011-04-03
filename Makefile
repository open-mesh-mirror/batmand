#
# Copyright (C) 2006-2009 B.A.T.M.A.N. contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

# activate this variable to deactivate policy routing for backward compatibility
#NO_POLICY_ROUTING = -DNO_POLICY_ROUTING

CC =		gcc
CFLAGS +=	-pedantic -Wall -W -Os -g3 -std=gnu99
EXTRA_CFLAGS =	-DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA $(NO_POLICY_ROUTING) -DREVISION_VERSION=$(REVISION_VERSION)
LDFLAGS +=	-lpthread

SBINDIR =	$(INSTALL_PREFIX)/usr/sbin

UNAME =		$(shell uname)
POSIX_C =	posix/init.c posix/posix.c posix/tunnel.c posix/unix_socket.c
BSD_C =		bsd/route.c bsd/tun.c bsd/kernel.c bsd/compat.c

ifeq ($(UNAME),Linux)
OS_C =		linux/route.c linux/tun.c linux/kernel.c $(POSIX_C)
endif

ifeq ($(UNAME),Darwin)
OS_C =		$(BSD_C) $(POSIX_C)
endif

ifeq ($(UNAME),GNU/kFreeBSD)
OS_C =		$(BSD_C) $(POSIX_C)
LDFLAGS +=	-lfreebsd -lbsd
endif

ifeq ($(UNAME),FreeBSD)
OS_C =		$(BSD_C) $(POSIX_C)
endif

ifeq ($(UNAME),OpenBSD)
OS_C =		$(BSD_C) $(POSIX_C)
endif

SRC_C= batman.c originator.c schedule.c list-batman.c allocate.c bitarray.c hash.c profile.c ring_buffer.c hna.c $(OS_C)
SRC_H= batman.h originator.h schedule.h list-batman.h os.h allocate.h bitarray.h hash.h profile.h packet.h types.h ring_buffer.h hna.h
SRC_O= $(SRC_C:.c=.o)

BINARY_NAME =	batmand

REVISION :=	$(shell if [ -d .svn ]; then svn info | grep "Rev:" | sed -e '1p' -n | awk '{print $$4}'; else if [ -d ~/.svk ]; then echo $$(svk info | grep "Mirrored From" | awk '{print $$5}'); fi; fi)
REVISION_VERSION =\"\ rv$(REVISION)\"

NUM_CPUS = $(shell NUM_CPUS=`cat /proc/cpuinfo | grep -v 'model name' | grep processor | tail -1 | awk -F' ' '{print $$3}'`;echo `expr $$NUM_CPUS + 1`)


all:
	$(MAKE) -j $(NUM_CPUS) $(BINARY_NAME)

$(BINARY_NAME): $(SRC_O) $(SRC_H) Makefile
	$(Q_LD)$(CC) -o $@ $(SRC_O) $(LDFLAGS)

.c.o:
	$(Q_CC)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -MD -c $< -o $@
-include $(SRC_C:.c=.d)

clean:
	rm -f $(BINARY_NAME) *.o posix/*.o linux/*.o bsd/*.o
	rm -f `find . -name '*.d' -print`

install:
	mkdir -p $(SBINDIR)
	install -m 0755 $(BINARY_NAME) $(SBINDIR)
