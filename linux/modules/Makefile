PWD:=$(shell pwd)
ifeq ($(wildcard $(KERNELPATH)),)
KERNELPATH = /lib/modules/$(shell uname -r)/build
# sanity check: does KERNELPATH exist?
ifeq ($(shell cd $(KERNELPATH) && pwd),)
$(error $(KERNELPATH) is missing, please set KERNELPATH)
endif
export KERNELPATH
endif


UNAME:=$(shell uname -r)
LINUX24=2.4
LINUX_VERSION:=$(findstring $(LINUX24),$(UNAME))
REVISION= $(shell      if [ -d ../../.git ]; then \
                               echo $$(git describe --always --dirty 2> /dev/null || echo "[unknown]"); \
                        fi)

include $(PWD)/Makefile.kbuild

ifeq ($(LINUX_VERSION),$(LINUX24))
TARGET:=batgat
INCLUDE:=-I/lib/modules/$(UNAME)/build/include -I/usr/src/kernel-headers-$(UNAME)/include
EXTRA_CFLAGS+=-D__KERNEL__ -DMODULE -O2 -Wall $(INCLUDE)
CC:=gcc
endif

ifneq ($(LINUX_VERSION),$(LINUX24))

all:
	$(MAKE) -C $(KERNELPATH) REVISION=$(REVISION) M=$(PWD) PWD=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELPATH) M=$(PWD) PWD=$(PWD) clean
else

clean:
	rm -f *.o *~
endif
