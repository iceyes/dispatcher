#
# Makefile for the DISPATCHER modules on top of IPv4.
#

# DISPATCHER transport protocol host load balancing support
dispatcher_proto-objs-y :=
dispatcher_proto-objs-y += dispatcher_proto_tcp.o
#dispatcher_proto-objs-y += dispatcher_proto_udp.o
#dispatcher_proto-objs-y += dispatcher_proto_ah_esp.o
#dispatcher_proto-objs-y += dispatcher_proto_sctp.o

dispatcher-objs :=	dispatcher_core.o dispatcher_ctl.o \
		dispatcher_nat.o	   		   \
		dispatcher_proto.o			   \
		$(dispatcher_proto-objs-y)


# DISPATCHER core
obj-m += dispatcher.o

# DISPATCHER application helpers
#EXTRA_CFLAGS+=-DCONFIG_DISPATCHER_DEBUG
EXTRA_CFLAGS+=-DCONFIG_DISPATCHER_PROTO_TCP

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
install:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules_install
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
