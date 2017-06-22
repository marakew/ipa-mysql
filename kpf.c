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
  "@(#)$Id: kpf.c,v 1.3.2.7 2003/05/27 18:50:48 simon Exp $";
#endif /* !lint */

#include "kpf.h"

#ifdef WITH_PF

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include "debug.h"

#define PFDEV	"/dev/pf"

u_quad_t	*kpf;
u_int		nkpf;

int		use_pf;		/* 1, if some rule{} uses "pf" parameter. */

static const char	*kpfdev = PFDEV;
static int		kpffd = -1;

/*
 * Init Packet Filter support: open /dev/pf device.
 */
int
kpf_init(void)
{
	syslog(LOG_INFO, "init Packet Filter support");
	if ( (kpffd = open(kpfdev, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "kpf_init: open(%s, O_RDONLY): %m", kpfdev);
		syslog(LOG_ERR, "Packet Filter is not configured in the kernel or doesn't work properly");
		return -1;
	}
	if (debug_pf > 0)
		syslog(LOG_INFO, "kpf_init: %s opened, FD %d", kpfdev, kpffd);
	kpf = NULL;
	nkpf = 0;
	return 0;
}

/*
 * Remover Packet Filter support: close descriptor for opened /dev/pf.
 */
void
kpf_close(void)
{
	syslog(LOG_INFO, "remove Packet Filter support");
	if (kpffd != -1) {
		if (close(kpffd) < 0)
			syslog(LOG_ERR, "kpf_close: close(FD %d (%s)): %m",
			    kpffd, kpfdev);
		kpffd = -1;
	}
	free(kpf);
}

/*
 * Dump PF rules to syslog(3).
 */
static void
kpf_dump_table(void)
{
#define TXT_BUF_LEN 60
	char		txt_buf[TXT_BUF_LEN + 1];
	u_int		i;
	int		len, total_len = 0;
	char		one_rule[1 + 10 + 1];
	 /*
	  *  1 - ' '
	  * 10 - length of rule number (u_int)
	  *  1 - '\0'
	  */

	if (nkpf == 0) {
		syslog(LOG_INFO, "kpf_dump_table: PF table is empty");
		return;
	}
	syslog(LOG_INFO, "kpf_dump_table: dump PF table:");
	for (i = 0; i < nkpf; ++i) {
		len = snprintf(one_rule, sizeof(one_rule), " %u", i);
		if (len < 0)
			syslog(LOG_ERR, "kpf_dump_table: snprintf failed: %m");
		else if (len + 1 > sizeof(one_rule))
			syslog(LOG_ERR, "kpf_dump_table: not enough space (%d chars) in one_rule", len + 1);
		else {
			len = strlen(one_rule);
			if (total_len + len > TXT_BUF_LEN) {
				syslog(LOG_INFO, "  **%s", txt_buf);
				total_len = 0;
			}
			strcpy(txt_buf + total_len, one_rule);
			total_len += len;
		}
	}
	if (total_len != 0)
		/* Log the rest of txt_buf. */
		syslog(LOG_INFO, "  **%s", txt_buf);
#undef TXT_BUF_LEN
}

/*
 * Read the table of PF rules from the kernel.
 * Reallocate internal structures if needed.
 */
int
kpf_read_table(void)
{
	u_int		i;
	struct pfioc_rule	pfr;

#ifdef PF_ANCHOR_NAME_SIZE
	memset(&pfr, 0, sizeof pfr);
	pfr.rule.action = PF_PASS;
#endif
	if (ioctl(kpffd, DIOCGETRULES, &pfr) < 0) {
		syslog(LOG_ERR, "kpf_read_table: ioctl(DIOCGETRULES): %m");
		return -1;
	}
	if (nkpf != pfr.nr) {
		if ( (kpf = realloc(kpf, pfr.nr * sizeof *kpf)) == NULL) {
			syslog(LOG_ERR, "kpf_read_table: realloc(%u bytes): %m",
			    pfr.nr * sizeof *kpf);
			return -1;
		}
		nkpf = pfr.nr;
		if (debug_pf > 0)
			syslog(LOG_INFO, "kpf_read_table: realloc, nkpf = %u", nkpf);
	}
	for (i = 0; i < nkpf; ++i) {
		pfr.nr = i;
		if (ioctl(kpffd, DIOCGETRULE, &pfr) < 0) {
			syslog(LOG_ERR, "kpf_read_table: ioctl(DIOCGETRULE, nr = %u): %m", i);
			return -1;
		}
		kpf[i] = pfr.rule.bytes;
	}

	if (debug_pf > 1)
		kpf_dump_table();

	return 0;
}

#endif /* WITH_PF */
