/*-
 * Copyright (c) 2001-2003 Andrey Simonenko
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char rcsid[] =
  "@(#)$Id: kip6fw.c,v 1.5.2.5 2003/05/27 18:50:48 simon Exp $";
#endif /* !lint */

#include "kip6fw.h"

#ifdef WITH_IP6FW

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>

#include "debug.h"

u_quad_t	kip6fw_bcnt_max;/* Max value of IPv6 Firewall byte counter. */
struct ip6_fw	*kip6fw;

int		use_ip6fw;	/* 1, if some rule{} uses "ip6fw" parameter. */

static int	sd = -1;
static int	nbytes, nbytesalloc;

/*
 * Init IPv6 Firewall support: open raw socket.
 */
int
kip6fw_init(void)
{
	struct ip6_fw	tmp;

	syslog(LOG_INFO, "preinit IPv6 Firewall support");
	if ( (sd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
		syslog(LOG_ERR, "kip6fw_init: socket(AF_INET6, SOCK_RAW, IPPROTO_RAW): %m");
		return -1;
	}
	kip6fw = NULL;
	nbytesalloc = 0;

	switch (sizeof(tmp.fw_bcnt)) {
	case 4:
		kip6fw_bcnt_max = ULONG_MAX;
		break;
	case 8:
		kip6fw_bcnt_max = UQUAD_MAX;
		break;
	default:
		syslog(LOG_ERR, "kip6fw_init: unsupported size of fw_bcnt (%d bytes) in struct ip6_fw",
		    sizeof(tmp.fw_bcnt));
		return -1;
	}

	if (debug_ip6fw > 0) {
		syslog(LOG_INFO, "kip6fw_init: raw socket opened, FD %d", sd);
		syslog(LOG_INFO, "kip6fw_init: sizeof(struct ip6_fw) = %u, sizeof(fw_bcnt) = %u",
		    sizeof tmp, sizeof tmp.fw_bcnt);
	}
	return 0;
}

/*
 * Dump IPFW rules to syslog(3).
 */
static void
kip6fw_dump_table(void)
{
#define TXT_BUF_LEN 60
	char		txt_buf[TXT_BUF_LEN + 1];
	int		len, total_len = 0;
	u_int		subnumber = 0;
	int		prevnum = -1;
	struct ip6_fw	*kfwp;
	char		one_rule[1 + 5 + 1 + 10 + 1];
	/*
	 *  1 - ' '
	 *  5 - length of rule number (u_short)
	 *  1 - '.'
	 * 10 - length of subnumber (u_int)
	 *  1 - '\0'
	 */

	syslog(LOG_INFO, "kip6fw_read_table: dump IP6FW table:");
	for (kfwp = kip6fw;; ++kfwp) {
		if (prevnum == kfwp->fw_number)
			++subnumber;
		else {
			prevnum = kfwp->fw_number;
			subnumber = 0;
		}
		if (subnumber == 0)
			len = snprintf(one_rule, sizeof(one_rule), " %hu", kfwp->fw_number);
		else
			len = snprintf(one_rule, sizeof(one_rule), " %hu.%u", kfwp->fw_number, subnumber);
		if (len < 0)
			syslog(LOG_ERR, "kip6fw_dump_table: snprintf failed: %m");
		else if (len + 1 > sizeof(one_rule))
			syslog(LOG_ERR, "kip6fw_dump_table: not enough space (%d chars) in one_rule", len + 1);
		else {
			len = strlen(one_rule);
			if (total_len + len > TXT_BUF_LEN) {
				syslog(LOG_INFO, "  **%s", txt_buf);
				total_len = 0;
			}
			strcpy(txt_buf + total_len, one_rule);
			total_len += len;
		}
		if (kfwp->fw_number == IP6FW_NUMBER_MAX)
			break;
	}
	if (total_len != 0)
		/* Log the rest of txt_buf. */
		syslog(LOG_INFO, "  **%s", txt_buf);
#undef TXT_BUF_LEN
}

/*
 * Read table of IP6FW rules from kernel. Realloc internal structures
 * if needed.
 */
int
kip6fw_read_table(void)
{
	if (kip6fw != NULL) {
		nbytes = nbytesalloc;
		if (getsockopt(sd, IPPROTO_IPV6, IPV6_FW_GET, kip6fw, &nbytes) < 0
		    && errno != EINVAL) {
			syslog(LOG_ERR, "kip6fw_read_table: getsockopt(IPV6_FW_GET): %m");
			syslog(LOG_ERR, "IPv6 Firewall is not configured in the kernel or doesn't work properly");
			return -1;
		}
		if (debug_ip6fw > 0)
			syslog(LOG_INFO, "kip6fw_read_table: nbytes = %d, nbytesalloc = %d",
			    nbytes, nbytesalloc);
	}
	if (nbytes >= nbytesalloc) {
		/* There are some data more in the IP6FW kernel table. */
		while (nbytes >= nbytesalloc) {
			nbytes = nbytesalloc += 20 * sizeof *kip6fw;
			if ( (kip6fw = realloc(kip6fw, nbytes)) == NULL) {
				syslog(LOG_ERR, "kip6fw_read_table: realloc(%d bytes): %m", nbytes);
				return -1;
			}
			if (getsockopt(sd, IPPROTO_IPV6, IPV6_FW_GET, kip6fw, &nbytes) < 0
			    && errno != EINVAL) {
				syslog(LOG_ERR, "kip6fw_read_table: getsockopt(IPV6_FW_GET): %m");
				syslog(LOG_ERR, "IPv6 Firewall is not configured in the kernel or doesn't work properly");
				return -1;
			}
			if (debug_ip6fw > 0)
				syslog(LOG_INFO, "kip6fw_read_table: increase table: bytes = %d, nbytesalloc = %d",
				    nbytes, nbytesalloc);
		}
	} else if (nbytesalloc - nbytes > 30 * sizeof *kip6fw) {
		/* Realloc memory if we have too much. */
		nbytesalloc = nbytes + 10 * sizeof *kip6fw;
		if ( (kip6fw = realloc(kip6fw, nbytes)) == NULL) {
			syslog(LOG_ERR, "kip6fw_read_table: realloc(%d bytes): %m", nbytesalloc);
			return -1;
		}
		if (debug_ip6fw > 0)
			syslog(LOG_INFO, "kip6fw_read_table: decrease table: nbytesalloc = %d",
			    nbytesalloc);
	}
	if (debug_ip6fw > 1)
		kip6fw_dump_table();

	return 0;
}

/*
 * Remove IPv6 Firewall support: close descriptor for opened socket.
 */
void
kip6fw_close(void)
{
	syslog(LOG_INFO, "remove IPv6 Firewall support");
	if (sd != -1) {
		if (close(sd) < 0)
			syslog(LOG_ERR, "kip6fw_close: close(FD %d): %m", sd);
		sd = -1;
	}
	free(kip6fw);
}

#endif /* WITH_IP6FW */
