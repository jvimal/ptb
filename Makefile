obj-m += sch_ptb.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`
