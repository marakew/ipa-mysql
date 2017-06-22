/*-
 * Copyright (c) 1999-2003 Andrey Simonenko
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
  "@(#)$Id: kipfw.c,v 1.6.2.3 2003/04/14 20:21:55 simon Exp $";
#endif /* !lint */

#include "kipfw.h"

#ifdef WITH_IPFW

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>

#include "debug.h"

u_quad_t	kipfw_bcnt_max;	/* Max value of IP Firewall byte counter. */
struct ip_fw	*kipfw;

int		use_ipfw;	/* 1, if some rule{} uses "ipfw" parameter. */

static int	sd = -1;
static int	nbytes, nbytesalloc;

/*
 * Init IP Firewall support: open raw socket.
 */
int
kipfw_init(void)
{
	struct ip_fw	tmp;

	syslog(LOG_INFO, "preinit IPv4 Firewall support");
	if ( (sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		syslog(LOG_ERR, "kipfw_init: socket(AF_INET, SOCK_RAW, IPPROTO_RAW): %m");
		return -1;
	}
	kipfw = NULL;
	nbytesalloc = 0;

	switch (sizeof(IPFW_BCNT(tmp))) {
	case 4:
		kipfw_bcnt_max = ULONG_MAX;
		break;
	case 8:
		kipfw_bcnt_max = UQUAD_MAX;
		break;
	default:
		syslog(LOG_ERR, "kipfw_init: unsupported size of fw_bcnt (%d bytes) in struct ip_fw",
		    sizeof IPFW_BCNT(tmp));
		return -1;
	}

	if (debug_ipfw > 0) {
		syslog(LOG_INFO, "kipfw_init: raw socket opened, FD %d", sd);
		syslog(LOG_INFO, "kipfw_init: sizeof(struct ip_fw) = %u, sizeof(fw_bcnt) = %u",
		    sizeof tmp, sizeof IPFW_BCNT(tmp));
	}

	return 0;
}

/*
 * Dump IPFW rules to syslog(3).
 */
static void
kipfw_dump_table(void)
{
#define TXT_BUF_LEN 60
	char		txt_buf[TXT_BUF_LEN + 1];
	int		len, total_len = 0;
	u_int		subnumber = 0;
	int		prevnum = -1;
	struct ip_fw	*kfwp;
	char		one_rule[1 + 5 + 1 + 10 + 1];
	/*
	 *  1 - ' '
	 *  5 - length of rule number (u_short)
	 *  1 - '.'
	 * 10 - length of subnumber (u_int)
	 *  1 - '\0'
	 */

	syslog(LOG_INFO, "kipfw_dump_table: dump IPFW table:");
#ifdef IPFW2
	for (kfwp = kipfw;; kfwp = (void *)kfwp + RULESIZE(kfwp)) {
#else
	for (kfwp = kipfw;; ++kfwp) {
#endif /* IPFW2 */
		if (prevnum == IPFWP_NUMBER(kfwp))
			++subnumber;
		else {
			prevnum = IPFWP_NUMBER(kfwp);
			subnumber = 0;
		}
		if (subnumber == 0)
			len = snprintf(one_rule, sizeof(one_rule), " %hu", IPFWP_NUMBER(kfwp));
		else
			len = snprintf(one_rule, sizeof(one_rule), " %hu.%u", IPFWP_NUMBER(kfwp), subnumber);
		if (len < 0)
			syslog(LOG_ERR, "kipfw_dump_table: snprintf failed: %m");
		else if (len + 1 > sizeof(one_rule))
			syslog(LOG_ERR, "kipfw_dump_table: not enough space (%d chars) in one_rule", len + 1);
		else {
			len = strlen(one_rule);
			if (total_len + len > TXT_BUF_LEN) {
				syslog(LOG_INFO, "  **%s", txt_buf);
				total_len = 0;
			}
			strcpy(txt_buf + total_len, one_rule);
			total_len += len;
		}
		if (IPFWP_NUMBER(kfwp) == IPFW_NUMBER_MAX)
			break;
	}
	if (total_len != 0)
		/* Log the rest of txt_buf. */
		syslog(LOG_INFO, "  **%s", txt_buf);
#undef TXT_BUF_LEN
}

/*
 * Read the table of IPFW rules from the kernel.
 * Reallocate internal structures if needed.
 */
int
kipfw_read_table(void)
{
	if (kipfw != NULL) {
		nbytes = nbytesalloc;
		if (getsockopt(sd, IPPROTO_IP, IP_FW_GET, kipfw, &nbytes) < 0) {
			syslog(LOG_ERR, "kipfw_read_table: getsockopt(IP_FW_GET): %m");
			syslog(LOG_ERR, "IPv4 Firewall is not configured in the kernel or doesn't work properly");
			return -1;
		}
		if (debug_ipfw > 0)
			syslog(LOG_INFO, "kipfw_read_table: nbytes = %d, nbytesalloc = %d",
			    nbytes, nbytesalloc);
	}
	if (nbytes >= nbytesalloc) {
		/* There are some data more in the IPFW kernel table. */
		while (nbytes >= nbytesalloc) {
			nbytes = nbytesalloc += 20 * sizeof *kipfw;
			if ( (kipfw = realloc(kipfw, nbytes)) == NULL) {
				syslog(LOG_ERR, "kipfw_read_table: realloc(%d bytes): %m", nbytes);
				return -1;
			}
			if (getsockopt(sd, IPPROTO_IP, IP_FW_GET, kipfw, &nbytes) < 0) {
				syslog(LOG_ERR, "kipfw_read_table: getsockopt(IP_FW_GET): %m");
				syslog(LOG_ERR, "IPv4 Firewall is not configured in the kernel or doesn't work properly");
				return -1;
			}
			if (debug_ipfw > 0)
				syslog(LOG_INFO, "kipfw_read_table: increase table: nbytes = %d, nbytesalloc = %d",
				    nbytes, nbytesalloc);
		}
	} else if (nbytesalloc - nbytes > 30 * sizeof *kipfw) {
		/* 
		 * Realloc memory if we have too much.
		 * This is not logical clear for IPFW2, because IPFW2 rules
		 * don't have fixed size, nevertheless this code is correct.
		 */
		nbytesalloc = nbytes + 10 * sizeof *kipfw;
		if ( (kipfw = realloc(kipfw, nbytesalloc)) == NULL) {
			syslog(LOG_ERR, "kipfw_read_table: realloc(%d bytes): %m", nbytesalloc);
			return -1;
		}
		if (debug_ipfw > 0)
			syslog(LOG_INFO, "kipfw_read_table: decrease table: nbytesalloc = %d",
			    nbytesalloc);
	}

	if (debug_ipfw > 1)
		kipfw_dump_table();

	return 0;
}


int
kipfw_zero_table(int number){
#if __FreeBSD_version < 500000  /* 4.11 */
	struct ip_fw rule;
#else
	int	rule;
#endif
	int nbytes;

#if __FreeBSD_version < 500000  /* 4.11 */
		memset(&rule, 0, sizeof(rule));
		rule.fw_number = number;
#else
		rule = number;
#endif
		nbytes = sizeof(rule);

//		syslog(LOG_ERR, "%s: ZERO %d\n", __FUNCTION__, number);

		if (setsockopt(sd, IPPROTO_IP, IP_FW_ZERO, &rule, nbytes) < 0) {
			syslog(LOG_ERR, "%s: setsockopt(IP_FW_ZERO): %m", __FUNCTION__);
			return -1;
		}
}

int
kipfw_delete_table(struct ip_fw *kipfw_){

#if __FreeBSD_version < 500000  /* 4.11 */
	struct ip_fw rule;
#else
	int rule;
#endif
	int nbytes;

#if __FreeBSD_version < 500000  /* 4.11 */
	memset(&rule, 0, sizeof(rule));
	rule.fw_number = kipfw_->fw_number;
#else
	rule = kipfw_->rulenum;
#endif
	nbytes = sizeof(rule);

#if 1
		if (setsockopt(sd, IPPROTO_IP, IP_FW_DEL, &rule, nbytes) < 0)
		{
			syslog(LOG_ERR, "%s: setsockopt(IP_FW_DEL): %m", __FUNCTION__);
			return -1;
		}
#endif
	return 1;
}

int
kipfw_add_table(struct ip_fw *kipfw_, int state){
	struct ip_fw rule;
	int nbytes;

	memcpy(&rule, kipfw_, sizeof(rule));
	nbytes = sizeof(rule);
#if 0
	rule.fw_pcnt = 0;
	rule.fw_bcnt = 0;
#endif	
#if __FreeBSD_version < 500000  /* 4.11 */
	rule.fw_flg = ((rule.fw_flg >> 8)<< 8) | state;
#else
	rule.act_ofs = 0;
	rule.cmd_len = 1;
	rule.cmd[0].len = 1;
	rule.cmd[0].opcode = state; //O_ACCEPT : O_DENY
#endif

			syslog(LOG_ERR, "%s: add %d  %qu packet %qu byte\n", __FUNCTION__,
#if __FreeBSD_version < 500000  /* 4.11 */
				rule.fw_number, rule.fw_pcnt, rule.fw_bcnt);
#else
				rule.rulenum, rule.pcnt, rule.bcnt);
#endif

#if 1
		if (getsockopt(sd, IPPROTO_IP, IP_FW_ADD, &rule, &nbytes) < 0) {
			syslog(LOG_ERR, "%s: getsockopt(IP_FW_ADD): %m", __FUNCTION__);
			return -1;
		}
#endif
	return 1;
}

int
kipfw_change_table(struct ip_fw *kipfw_, int state){
	int fw_flg;

	--kipfw_;

#if __FreeBSD_version < 500000	/* 4.11 */
	fw_flg = kipfw_->fw_flg & IP_FW_F_COMMAND;
	if ((fw_flg == IP_FW_F_DENY && state == IP_FW_F_DENY) ||
	    (fw_flg == IP_FW_F_COUNT && state == IP_FW_F_COUNT))
#else /* 5.x */
//	fw_flg = ((ipfw_insn *)ACTION_PTR(kipfw))->opcode;
	fw_flg = kipfw_->cmd[0].opcode;
	if ((fw_flg == O_DENY && state == O_DENY) ||
	    (fw_flg == O_COUNT && state == O_COUNT))
#endif
		return 0;

	if ( kipfw_delete_table(kipfw_) < 0)
		return -1;

	if ( kipfw_add_table(kipfw_, state) < 0)
		return -1;

	return 1;
}


/*
 * Remove IP Firewall support: close descriptor for opened socket.
 */
void
kipfw_close(void)
{
	syslog(LOG_INFO, "remove IPv4 Firewall support");
	if (sd != -1) {
		if (close(sd) < 0)
			syslog(LOG_ERR, "kipfw_close: close(FD %d): %m", sd);
		sd = -1;
	}
	free(kipfw);
}

#endif /* WITH_IPFW */
