/* bsdos.h

   System dependencies for BSDI BSD/OS... */

/*
 * Copyright (c) 2004,2007,2009 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   https://www.isc.org/
 *
 * This software has been written for Internet Systems Consortium
 * by Ted Lemon in cooperation with Vixie Enterprises and Nominum, Inc.
 * To learn more about Internet Systems Consortium, see
 * ``https://www.isc.org/''.  To learn more about Vixie Enterprises,
 * see ``http://www.vix.com''.   To learn more about Nominum, Inc., see
 * ``http://www.nominum.com''.
 */

#include <syslog.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <paths.h>
#include <errno.h>
#include <unistd.h>
#include <setjmp.h>
#include <limits.h>

#include <sys/wait.h>
#include <signal.h>

extern int h_errno;

#include <net/if.h>
#include <net/if_dl.h>
#define INADDR_LOOPBACK	((u_int32_t)0x7f000001)

/* Varargs stuff... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define va_dcl
#define VA_start(list, last) va_start (list, last)

#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"/var/run/dhcpd.pid"
#endif
#ifndef _PATH_DHCPD6_PID
#define _PATH_DHCPD6_PID "/var/run/dhcpd6.pid"
#endif
#ifndef _PATH_DHCPD_DB
#define _PATH_DHCPD_DB "/var/db/dhcpd.leases"
#endif
#ifndef _PATH_DHCPD6_DB
#define _PATH_DHCPD6_DB "/var/db/dhcpd6.leases"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID "/var/run/dhclient.pid"
#endif
#ifndef _PATH_DHCLIENT6_PID
#define _PATH_DHCLIENT6_PID "/var/run/dhclient6.pid"
#endif
#ifndef _PATH_DHCLIENT_DB
#define _PATH_DHCLIENT_DB "/var/db/dhclient.leases"
#endif
#ifndef _PATH_DHCLIENT6_DB
#define _PATH_DHCLIENT6_DB "/var/db/dhclient6.leases"
#endif

#define EOL	'\n'
#define VOIDPTR void *

/* Time stuff... */
#include <sys/time.h>
#define TIME time_t
#define GET_TIME(x)	time ((x))

#define HAVE_SA_LEN

#if defined (USE_DEFAULT_NETWORK)
#  define USE_BPF
#endif

#if _BSDI_VERSION < 199802
typedef int socklen_t;
#endif

#ifdef NEED_PRAND_CONF
const char *cmds[] = {
	"/bin/ps -axlw 2>&1",
	"/usr/sbin/arp -an 2>&1",
	"/usr/sbin/netstat -an 2>&1",
	"/bin/df  2>&1",
	"/usr/bin/dig com. soa +ti=1 +retry=0 2>&1",
	"/usr/ucb/uptime  2>&1",
	"/usr/sbin/netstat -an 2>&1",
	"/usr/sbin/iostat  2>&1",
	"/usr/sbin/vmstat  2>&1",
	NULL
};

const char *dirs[] = {
	"/tmp",
	"/var/tmp",
	".",
	"/",
	"/var/spool",
	"/dev",
	"/var/mail",
	"/usr/home",
	NULL
};

const char *files[] = {
	"/var/log/messages",
	"/var/log/wtmp",
	"/var/log/lastlog",
	NULL
};
#endif /* NEED_PRAND_CONF */
