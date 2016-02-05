/* utils.c

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

#include <sys/ioctl.h>

#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netlink/netlink.h>
#include <netlink/route/link/bridge.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>

#include "utils.h"

#define ERR(fmt, ...) log_error("err: " fmt "\n", __VA_ARGS__)

#define ASSERT_NO_ERR(_err) if (_err) {                                 \
		ERR("%s:%d %s: %d", __FILE__, __LINE__, __func__, (_err));        \
		return (_err);                                                    \
	}

#define ASSERT_NO_ERR_VOID(_err) if (_err) {                            \
		ERR("%s:%d %s: %d", __FILE__, __LINE__, __func__, (_err));        \
		return;                                                           \
	}

#define ASSERT_NO_ERR_GOTO(_err, _label) if (_err) {                    \
		ERR("%s:%d %s: %d", __FILE__, __LINE__, __func__, (_err));        \
		goto _label;                                                      \
	}

struct cb_data
{
	int err;
	int vid;
	struct interface_info *parent;
};

static int get_vid_by_iface (const char *iface) {
	int vid = -1;

	int fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd > 0) {
		struct vlan_ioctl_args vlargs;
		vlargs.cmd = GET_VLAN_VID_CMD;
		strcpy (vlargs.device1, iface);
		if (ioctl (fd, SIOCGIFVLAN, &vlargs) == 0) {
			vid = vlargs.u.VID;
			log_debug ("Interface %s is vlan interface for vid %u",
				iface, vid);
		}
	}
	return vid;
}

static int register_interface_child (struct interface_info *owner, int ifindex) {
	isc_result_t status;
	struct interface_info *child = NULL;
	struct in_addr client_if_address = { .s_addr = 0 };
	struct nl_cache *cache;
	int err = 0;
	int i;

	struct nl_sock *sk;
	sk = nl_socket_alloc ();
	if (!sk)
		return -ENOMEM;

	err = nl_connect (sk, NETLINK_ROUTE);
	ASSERT_NO_ERR_GOTO(err, free_sk);

	err = rtnl_link_alloc_cache (sk, AF_BRIDGE, &cache);

	ASSERT_NO_ERR(err);

	err = nl_cache_refill (sk, cache);
	ASSERT_NO_ERR_GOTO(err, err_free_cache);

	struct rtnl_link *link = rtnl_link_get (cache, ifindex);
	char *child_name = rtnl_link_get_name (link);
	if (child_name) {
		child = find_iface(child_name);
		if (!child) {
			status = interface_allocate(&child, MDL);
			if (status != ISC_R_SUCCESS)
				log_fatal ("%s: interface_allocate: %s",
					child_name, isc_result_totext (status));
			strcpy (child->name, child_name);
			add_ipv4_addr_to_interface (child, &client_if_address);
			interface_snorf (child, INTERFACE_REQUESTED);
		}
		interface_reference (&child->parent_ip,
			find_iface (owner->name), MDL);
		interface_dereference (&child, MDL);
	}

	err_free_cache: nl_cache_free (cache);

	free_sk: nl_socket_free (sk);

	return err;
}

/*
 * Add as interface child if untagged in parents vlan.
 */
static int check_register_child (struct rtnl_link *link, const struct bridge_vlan_info *br_vinfo, void *data) {
	struct cb_data *cbd = data;
	int port = rtnl_link_get_ifindex (link);

	assert (cbd);

	/* Short-circuit if already an error */
	if (cbd->err)
		return 1;

	if (cbd->vid == br_vinfo->vid) {
		/* Only add if link is associated untagged with vlan. Also check master? */
		if (br_vinfo->flags & BRIDGE_VLAN_INFO_UNTAGGED) {
			register_interface_child (cbd->parent,
				rtnl_link_get_ifindex (link));
			cbd->parent->is_parent = 1;
		}
	}
	return 0;
}

/*
 * Iterate over links and check each link for registration.
 */
static void check_link (struct nl_object *obj, void *data) {
	struct cb_data *cbd = data;
	struct rtnl_link *link = (struct rtnl_link *) obj;
	/* Short-circuit if already an error */
	if (cbd->err)
		return;
	cbd->err = rtnl_link_bridge_vlan_foreach (link, check_register_child,
		cbd);
	ASSERT_NO_ERR_VOID(cbd->err);
}

int register_interface_children (struct interface_info *parent) {
	struct nl_sock *sk;
	struct nl_cache *cache;
	struct cb_data cbd = { .err = 0, .parent = parent };
	int err = 0;
	int vid = get_vid_by_iface (parent->name);

	if (vid < 0)
		return 1;
	cbd.vid = vid;

	sk = nl_socket_alloc ();
	if (!sk)
		return -ENOMEM;

	err = nl_connect (sk, NETLINK_ROUTE);
	ASSERT_NO_ERR_GOTO(err, free_sk);

	err = rtnl_link_alloc_cache (sk, AF_BRIDGE, &cache);
	ASSERT_NO_ERR_GOTO(err, free_sk);

	err = nl_cache_refill (sk, cache);
	ASSERT_NO_ERR_GOTO(err, err_free_cache);

	/* Collect information */
	nl_cache_foreach (cache, check_link, &cbd);
	err = cbd.err;
	ASSERT_NO_ERR_GOTO(err, err_free_cache);

	err_free_cache: nl_cache_free (cache);

	free_sk: nl_socket_free (sk);

	return err;
}

int get_ip_address (char *iface, struct in_addr *addr) {
	struct ifreq ifr;
	int fd;
	int err = 0;

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	//Type of address to retrieve - IPv4 IP address
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy (ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl (fd, SIOCGIFADDR, &ifr))
		err = 1;
	else
		*addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
	close (fd);
	return err;
}

const char *int_to_addr (int addr) {
	static char buf[16];
	struct sockaddr_in sa;
	return inet_ntop (AF_INET, &addr, buf, 16);
}

struct interface_info *find_iface (const char *if_name) {
	struct interface_info *out;
	for (out = interfaces; out; out = out->next) {
		if (!strcmp (if_name, out->name)) {
			break;
		}
	}
	return out;
}

int iface_mac (char *iface, unsigned char *addr) {
	int fd, ret = 0, save_errno = 0;
	static struct ifreq ifr;

	if (!iface || !addr) {
		errno = EINVAL;
		return 1;
	}

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 1;

	strncpy (ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	if (-1 == ioctl (fd, SIOCGIFHWADDR, &ifr)) {
		save_errno = errno;
		ret = 1;
	}
	else {
		memcpy (addr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	}

	close (fd);
	errno = save_errno; /* Restore errno if changed. */

	return ret;
}

int sys_inet_ntop (int addr, char *str, size_t len) {
	assert (str);

	if (!str || len < INET_ADDRSTRLEN)
		return 1;

	return !inet_ntop (AF_INET, &addr, str, len);
}

int iface_ip (const char *iface) {
	struct ifreq ifr;
	int fd, result, save_errno = 0;
	int request = SIOCGIFADDR;

	if (!iface) {
		errno = EINVAL;
		return -1;
	}

	if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	strncpy (ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_INET;
	if (-1 == ioctl (fd, request, &ifr)) {
		save_errno = errno;
		result = -1;
	}
	else {
		struct sockaddr_in *ip;

		/* The IP is being returned in network byte order.
		 * ifru_addr is of type sockaddr - hence typecast to sockaddr_in
		 * for getting ip address easily */
		ip = (struct sockaddr_in *) &ifr.ifr_addr;
		inet_aton (inet_ntoa (ip->sin_addr),
			(struct in_addr *) &result);
	}

	close (fd);

	if (result)
		errno = save_errno;

	return result;
}

/**
 * hex2buf - convert hex string to hex-buffer.
 * @hex_str: The string to convert, may start with '0x'.
 *           The hex string may be in the form of xx:xx:xx:xx.
 * @buf:     The buffer into which the hex values should be written.
 * @buflen:  The size of the buffer.
 *
 * Returns:
 * The number of bytes written into the buffer.
 */
int hex2buf (char *hex_str, u_int8_t *buf, int buflen) {
	int i = 0, odd = 0;

	if (!hex_str)
		return 0;
	if (!buf)
		return 0;

	/* Allow hex strings starting with 0x */
	if (hex_str[0] == '0' && hex_str[1] == 'x')
		hex_str += 2;

	/* When not using xx:xx form, handle case with odd number of hexadecimal digits */
	if ((strlen (hex_str) & 1) && !strchr (hex_str, ':') && !strchr (hex_str, '.'))
		odd = 1;

	for (i = 0; i < buflen && *hex_str && !isspace (*hex_str); i++) {
		char tmp[3];

		if (!isxdigit (*hex_str))
			return 0;

		if (odd) {
			tmp[0] = '0';
			odd = 0;
		}
		else {
			tmp[0] = *hex_str++;
		}

		if (!isxdigit (*hex_str))
			return 0;

		tmp[1] = *hex_str++;
		tmp[2] = 0;
		buf[i] = (u_int8_t) strtoul (tmp, NULL, 16);

		/* Allow hex strings in the form of xx:xx:xx:xx and peculiar quad-dotted xxxx.xxxx.xxxx */
		if (*hex_str == ':' || *hex_str == '.')
			hex_str++;
	}

	return i;
}
