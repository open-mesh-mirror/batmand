#!/usr/bin/make -f
# -*- makefile -*-
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

# batmand build
BINARY_NAME = batmand

UNAME =		$(shell uname)
POSIX_OBJ =	posix/init.o posix/posix.o posix/tunnel.o posix/unix_socket.o
BSD_OBJ =	bsd/route.o bsd/tun.o bsd/kernel.o bsd/compat.o
LINUX_OBJ =	linux/route.o linux/tun.o linux/kernel.o

ifeq ($(UNAME),Linux)
OS_OBJ =	$(LINUX_OBJ) $(POSIX_OBJ)
endif

ifeq ($(UNAME),Darwin)
OS_OBJ =	$(BSD_OBJ) $(POSIX_OBJ)
endif

ifeq ($(UNAME),GNU/kFreeBSD)
OS_OBJ =	$(BSD_OBJ) $(POSIX_OBJ)
LDLIBS +=	-lfreebsd -lbsd
endif

ifeq ($(UNAME),FreeBSD)
OS_OBJ =	$(BSD_OBJ) $(POSIX_OBJ)
endif

ifeq ($(UNAME),OpenBSD)
OS_OBJ =	$(BSD_OBJ) $(POSIX_OBJ)
endif

OBJ = batman.o originator.o schedule.o list-batman.o allocate.o bitarray.o hash.o profile.o ring_buffer.o hna.o $(OS_OBJ)
MANPAGE = man/batmand.8

# activate this variable to deactivate policy routing for backward compatibility
#NO_POLICY_ROUTING = -DNO_POLICY_ROUTING

# batmand flags and options
CFLAGS +=	-pedantic -Wall -W -std=gnu99 -MD
CPPFLAGS +=	-DDEBUG_MALLOC -DMEMORY_USAGE -DPROFILE_DATA $(NO_POLICY_ROUTING)
LDLIBS +=	-lpthread

# disable verbose output
ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

# standard build tools
CC ?=		gcc
RM ?= rm -f
INSTALL ?= install
MKDIR ?= mkdir -p
COMPILE.c = $(Q_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(Q_LD)$(CC) $(LDFLAGS) $(TARGET_ARCH)

# standard install paths
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man

# try to generate revision
REVISION= $(shell	if [ -d .git ]; then \
				echo $$(git describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
ifneq ($(REVISION),)
CPPFLAGS += -DSOURCE_VERSION=\"$(REVISION)\"
endif

# default target
all: $(BINARY_NAME)

# standard build rules
.SUFFIXES: .o .c
.c.o:
	$(COMPILE.c) -o $@ $<

$(BINARY_NAME): $(OBJ)
	$(LINK.o) $^ $(LDLIBS) -o $@

clean:
	$(RM) $(BINARY_NAME) $(OBJ) $(DEP)

install: $(BINARY_NAME)
	$(MKDIR) $(DESTDIR)$(SBINDIR)
	$(MKDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 0755 $(BINARY_NAME) $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0644 $(MANPAGE) $(DESTDIR)$(MANDIR)/man8

# load dependencies
DEP = $(OBJ:.o=.d)
-include $(DEP)

.PHONY: all clean install
