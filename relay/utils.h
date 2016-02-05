/* utils.h

   Utility functions for relay agent, contributed by Thomas Eliasson at
   Westermo Teleindustri AB, Sweden
 */

/*
 * Copyright (c) 2016  Thomas Eliasson <thomas.eliasson@westermo.se>
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
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include "dhcpd.h"

int register_interface_children(struct interface_info *parent);

int iface_mac (char *iface, unsigned char *addr);

int sys_inet_ntop (int addr, char *str, size_t len);

int iface_ip (const char *iface);

int hex2buf (char *hex_str, u_int8_t *buf, int buflen);

struct interface_info *find_iface(const char *if_name);

const char *int_to_addr(int addr);

int get_ip_address (char *iface, struct in_addr *addr);

#endif