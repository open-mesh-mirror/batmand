UNAME:=$(shell uname -r)
LINUX26=2.6
LINUX_VERSION:=$(findstring $(LINUX26),$(UNAME))
REVISION := "0.3"	
include $(PWD)/Makefile.kbuild

ifneq ($(LINUX_VERSION),$(LINUX26))
TARGET:=batgat
INCLUDE:=-I/lib/modules/$(UNAME)/build/include -I/usr/src/kernel-headers-$(UNAME)/include
EXTRA_CFLAGS+=-D__KERNEL__ -DMODULE -O2 -Wall $(INCLUDE)
CC:=gcc
endif

ifeq ($(LINUX_VERSION),$(LINUX26))

all:
	make -C /lib/modules/$(shell uname -r)/build REVISION=$(REVISION) M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
else

clean:
	rm -f *.o *~
endif
