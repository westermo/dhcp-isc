SRCS = dhcpd.c options.c errwarn.c convert.c conflex.c confpars.c \
       tree.c memory.c bootp.c dhcp.c alloc.c print.c socket.c \
       hash.c tables.c inet.c
PROG = dhcpd

.include <bsd.prog.mk>

CFLAGS += -DDEBUG -g -Wall -Wstrict-prototypes -Wno-unused \
	  -Wno-uninitialized -Werror
