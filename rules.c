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
  "@(#)$Id: rules.c,v 1.6.2.15 2003/11/11 10:23:42 simon Exp $";
#endif /* !lint */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <dirent.h>
#include <unistd.h>
#include <stdarg.h>
#include <regex.h>

#include "rules.h"

#include "cmd.h"
#include "common.h"
#include "config.h"
#include "db.h"
#include "debug.h"
#include "ipa.h"
#include "path.h"
#include "mysql.h"

struct rule_slisthead rule_head;

static SLIST_HEAD(, limit) wpid_head;

int		use_worktime;		/* 1, if anywhere "worktime" is used */
struct worktime	worktime_global[7];	/* global { worktime } */
struct commands	startup_global;		/* global { startup } */
struct commands	shutdown_global;	/* global { shutdown } */

static time_t	newday_time;		/* UTC time in seconds of next day */
static u_int	sleep_seconds;		/* how many seconds to sleep */
static int	process_mon = 0,	/* current month */
		process_year = 0;	/* current year */
static int	time_changed_flag = 0;	/* 1, if there is a problem with time/localtime */

static const u_quad_t	zero_ULL = 0ULL;
static const u_quad_t	uquad_max_ULL = UQUAD_MAX;

static volatile sig_atomic_t	reconfigure_flag = 0, need_rules_check = 0,
				wakeup_flag = 0, goingdown_flag = 0,
				db_dump_flag = 0, child_terminated_flag = 0;

static const char *wdays[] = {
	"Sunday", "Monday", "Tuesday", "Wednesday",
	"Thursday", "Friday", "Saturday"
};

static int	do_reconfigure(void);

static void	check_childs(void);

static int	check_rule_limits(const struct rule *, time_t *);
static void	add_chunk_to_rule_limits(const struct rule *, const u_quad_t *);
static void	sub_chunk_from_rule_limits(const struct rule *, const u_quad_t *);

static int	Ftruncate_Seek(FILE *, long, const char *);

static int	append_limit_z_ts(struct limit *);
static int	append_limit_e_ts(struct limit *);
static int	restart_limit(struct limit *);
static int	update_rule_limits(const struct rule *);

static time_t	mk_time_exp_upto(time_t, char);


/*
 * Add chunk to the counter of *rule and to counters of its limits.
 * Check if there are some "subtracted" bytes. Check for counter overflowing.
 */
static int
add_chunk_to_rule(struct rule *rule, const u_quad_t *chunk_ptr, struct ip_fw *kfwp)
{
	u_quad_t chunk = *chunk_ptr;

	if (rule->bcnt_sub >= chunk)
		rule->bcnt_sub -= chunk;
	else {
		chunk -= rule->bcnt_sub;
		rule->bcnt_sub = 0;
		if (rule->bcnt <= UQUAD_MAX - chunk)
			rule->bcnt += chunk;
		else {
			if (update_db(rule, &uquad_max_ULL) < 0)
				return -1;
#ifdef WITH_MYSQL
			update_sql_db(rule, &uquad_max_ULL);
			sql_billing(rule, kfwp);
#endif	
			rule->bcnt = UQUAD_MAX - rule->bcnt;
			rule->bcnt = chunk - rule->bcnt;
			if (append_db(rule, &rule->bcnt) < 0)
				return -1;
#ifdef WITH_MYSQL	
//			syslog(LOG_ERR, "%s:%d: append_sql_db\n", __FUNCTION__, __LINE__);
			append_sql_db(rule, &rule->bcnt);
#endif
		}
	}
	if (!SLIST_EMPTY(&rule->limit_head))
		add_chunk_to_rule_limits(rule, chunk_ptr);
	return 0;
}

/*
 * Subtract chunk from the counter of *rule and from counters of its limits.
 * Check for "subtracted" counter overflowing.
 */
static void
sub_chunk_from_rule(struct rule *rule, const u_quad_t *chunk_ptr)
{
	if (rule->bcnt >= *chunk_ptr)
		rule->bcnt -= *chunk_ptr;
	else {
		if (rule->bcnt_sub <= UQUAD_MAX - (*chunk_ptr - rule->bcnt))
			rule->bcnt_sub += *chunk_ptr - rule->bcnt;
		else {
			syslog(LOG_WARNING, "rule %s: wrong configuration of some accounting rule: \"subtracted\" counter overflowed",
			    rule->rulename);
			rule->bcnt_sub = UQUAD_MAX;
		}
		rule->bcnt = 0;
	}
	if (!SLIST_EMPTY(&rule->limit_head))
		sub_chunk_from_rule_limits(rule, chunk_ptr);
}

#ifdef WITH_IPFW
/*
 * Do IP accounting for *rule from the IPv4 Firewall table.
 */
static int
do_ipfwac_for_rule(struct rule *rule)
{
	u_int		i;
	int		seen_flag;
	int		prevnum = -1;	/* real value of number is u_short type */
	u_int		subnumber = 0;	/* initial value isn't used */
	u_quad_t	chunk = 0;	/* initial value isn't used */
	u_quad_t	maxchunk = rule->maxchunk;
	struct ipfwac	*fwacp = rule->ipfwac;
	struct ip_fw	*kfwp = kipfw;

	for (i = 0; i < rule->nipfwac; ++fwacp, ++i) {
#ifdef IPFW2
		for (seen_flag = 0; !seen_flag; kfwp = (void *)kfwp + RULESIZE(kfwp)) {
#else
		for (seen_flag = 0; !seen_flag; ++kfwp) {
#endif
			if (IPFWP_NUMBER(kfwp) > fwacp->number)
				break;
			if (prevnum == IPFWP_NUMBER(kfwp))
				++subnumber;
			else {
				prevnum = IPFWP_NUMBER(kfwp);
				subnumber = 0;
			}
			if (IPFWP_NUMBER(kfwp) == fwacp->number &&
			    subnumber == fwacp->subnumber) {
				/* found IPFW rule in kernel table */
				if (rule->state == 1){ /* block - dont count */
					IPFWP_BCNT(kfwp) = 0;
//					continue;
				}

				seen_flag = 1;
				if (fwacp->seen == 0) {
					fwacp->bcnt_old = IPFWP_BCNT(kfwp);
					fwacp->seen = 1;
					if (!rule->firstcall)
						syslog(LOG_WARNING, "rule %s: %hu.%u was added to IPFW kernel table",
						    rule->rulename, fwacp->number, fwacp->subnumber);
				} else if (fwacp->bcnt_old != IPFWP_BCNT(kfwp)) {
					if (fwacp->bcnt_old < IPFWP_BCNT(kfwp))
						chunk = IPFWP_BCNT(kfwp) - fwacp->bcnt_old;
					else {
						chunk = kipfw_bcnt_max - (fwacp->bcnt_old - IPFWP_BCNT(kfwp));
						if (maxchunk != 0) {
							if (chunk > maxchunk) {
								syslog(LOG_WARNING, "rule %s: was IPFW rule %hu.%u flushed? chunk = %s, maxchunk = %s",
								    rule->rulename, fwacp->number, fwacp->subnumber,
								    show_bytes(chunk), show_bytes2(maxchunk));
								chunk = IPFWP_BCNT(kfwp);
								syslog(LOG_INFO, "rule %s: use absolute value %s of IPFW %hu.%u counter",
								    rule->rulename, show_bytes(chunk), fwacp->number, fwacp->subnumber);
							}
						} else
							syslog(LOG_WARNING, "rule %s: IPFW counter %hu.%u was overflowed, old value = %s, current value = %s",
							    rule->rulename, fwacp->number, fwacp->subnumber, show_bytes(fwacp->bcnt_old), show_bytes2(IPFWP_BCNT(kfwp)));
					}
					fwacp->bcnt_old = IPFWP_BCNT(kfwp);
					if (fwacp->action == ADD) {
						if (add_chunk_to_rule(rule, &chunk, kfwp) < 0)
							return -1;
					} else /* fwacp->action == SUB */
						sub_chunk_from_rule(rule, &chunk);
				}
			}
			if (IPFWP_NUMBER(kfwp) == IPFW_NUMBER_MAX)
				break;
		}
		if (!seen_flag) {
			if (fwacp->seen != 0) {
				fwacp->seen = 0;
				syslog(LOG_WARNING, "rule %s: %hu.%u was removed from IPFW kernel table",
				    rule->rulename, fwacp->number, fwacp->subnumber);
			} else if (rule->firstcall)
				syslog(LOG_WARNING, "rule %s: %hu.%u doesn't exist in IPFW kernel table",
				    rule->rulename, fwacp->number, fwacp->subnumber);
		}
	}
	if (update_db(rule, &rule->bcnt) < 0)
		return -1;
#ifdef WITH_MYSQL
	update_sql_db(rule, &rule->bcnt);
	sql_billing(rule, kfwp);
#endif
	return update_rule_limits(rule);
}
#endif /* WITH_IPFW */

#ifdef WITH_IP6FW
/*
 * Do IP accounting for *rule from IPv6 Firewall table.
 */
static int
do_ip6fwac_for_rule(struct rule *rule)
{
	u_int		i;
	int		seen_flag;
	int		prevnum = -1;	/* real value of number is u_short type */
	u_int		subnumber = 0;	/* initial value isn't used */
	u_quad_t	chunk = 0;	/* initial value isn't used */
	u_quad_t	maxchunk = rule->maxchunk;
	struct ipfwac	*fwacp = rule->ip6fwac;
	struct ip6_fw	*kfwp = kip6fw;

	for (i = 0; i < rule->nip6fwac; ++fwacp, ++i) {
		for (seen_flag = 0; !seen_flag; ++kfwp) {
			if (kfwp->fw_number > fwacp->number)
				break;
			if (prevnum == kfwp->fw_number)
				++subnumber;
			else {
				prevnum = kfwp->fw_number;
				subnumber = 0;
			}
			if (kfwp->fw_number == fwacp->number &&
			    subnumber == fwacp->subnumber) {
				/* found IP6FW rule in kernel table */
				seen_flag = 1;
				if (fwacp->seen == 0) {
					fwacp->bcnt_old = kfwp->fw_bcnt;
					fwacp->seen = 1;
					if (!rule->firstcall)
						syslog(LOG_WARNING, "rule %s: %hu.%u was added to IP6FW kernel table",
						    rule->rulename, fwacp->number, fwacp->subnumber);
				} else if (fwacp->bcnt_old != kfwp->fw_bcnt) {
					if (fwacp->bcnt_old < kfwp->fw_bcnt)
						chunk = kfwp->fw_bcnt - fwacp->bcnt_old;
					else {
						chunk = kip6fw_bcnt_max - (fwacp->bcnt_old - kfwp->fw_bcnt);
						if (maxchunk != 0) {
							if (chunk > maxchunk) {
								syslog(LOG_WARNING, "rule %s: was IP6FW rule %hu.%u flushed? chunk = %s, maxchunk = %s",
								    rule->rulename, fwacp->number, fwacp->subnumber,
								    show_bytes(chunk), show_bytes2(maxchunk));
								chunk = kfwp->fw_bcnt;
								syslog(LOG_INFO, "rule %s: use absolute value %s of IP6FW %hu.%u counter",
								    rule->rulename, show_bytes(chunk), fwacp->number, fwacp->subnumber);
							}
						} else
							syslog(LOG_WARNING, "rule %s: IP6FW %hu.%u counter was overflowed, old value = %s, current value = %s",
							    rule->rulename, fwacp->number, fwacp->subnumber, show_bytes(fwacp->bcnt_old), show_bytes2(kfwp->fw_bcnt));
					}
					fwacp->bcnt_old = kfwp->fw_bcnt;
					if (fwacp->action == ADD) {
						if (add_chunk_to_rule(rule, &chunk) < 0)
							return -1;
					} else /* fwacp->action == SUB */
						sub_chunk_from_rule(rule, &chunk);
				}
			}
			if (kfwp->fw_number == IP6FW_NUMBER_MAX)
				break;
		}
		if (!seen_flag) {
			if (fwacp->seen != 0) {
				fwacp->seen = 0;
				syslog(LOG_WARNING, "rule %s: %hu.%u was removed from IP6FW kernel table",
				    rule->rulename, fwacp->number, fwacp->subnumber);
			} else if (rule->firstcall)
				syslog(LOG_WARNING, "rule %s: %hu.%u doesn't exist in IP6FW kernel table",
				    rule->rulename, fwacp->number, fwacp->subnumber);
		}
	}
	if (update_db(rule, &rule->bcnt) < 0)
		return -1;
#ifdef WITH_MYSQL
	update_sql_db(rule, &rule->bcnt);
#endif
	return update_rule_limits(rule);
}
#endif /* WITH_IP6FW */

#ifdef WITH_IPFIL
/*
 * Do IP accounting for *rule from IP Filter accounting tables.
 */
static int
do_ipfilac_for_rule(struct rule *rule)
{
	u_int		gi;	/* Group index. */
	u_int		ri;	/* Rule index. */
	u_int		kgi;	/* Kernel group index. */

	u_quad_t	chunk;
	u_quad_t	maxchunk = rule->maxchunk;

	/* For rule{} part. */
	u_int			group_number;
	struct ipfilac		*ipfilacp;
	struct ipfilac_group	*groupp;
	struct ipfilac_rule	*rulep;

	/* For kernel part. */
	u_quad_t		kbcnt;
	struct kipfil		*kipfilp;
	struct kipfil_group	*kgroupp;

	/* Start accounting for ingoing accounting rules. */
	ipfilacp = &rule->ipfilac_in;
	kipfilp = &kipfil_in;

	/*
	 * All data in kipfil_{in|out} and in rule->ipfilac_{in|out} are
	 * sorted in the same way: by group numbers (and neturaly by rule
	 * numbers).
	 */
next_do_ipfilac:
	kgroupp = kipfilp->group;
	kgi = 0;
	for (gi = 0, groupp = ipfilacp->group; gi < ipfilacp->ngroup; ++groupp, ++gi) {
		group_number = groupp->group_number;
		/*
		 * We need to write following two lines here, because we
		 * want to tell below which rules are not present in the kernel,
		 * but the group also can be absent in the kernel.
		 */
		ri = 0;
		rulep = groupp->rule;
		for (; kgi < kipfilp->ngroup && group_number >= kgroupp->group_number;
		    ++kgroupp, ++kgi)
			if (group_number == kgroupp->group_number) {
				/* We found group in IPFIL kernel table. */
				for (; ri < groupp->nrule && rulep->rule_number <= kgroupp->bcnt_size;
				    ++rulep, ++ri) {
					/* We found rule in kernel IPFIL group. */
					kbcnt = kgroupp->bcnt[rulep->rule_number - 1];
					if (!rulep->seen) {
						rulep->bcnt_old = kbcnt;
						rulep->seen = 1;
						if (!rule->firstcall)
							syslog(LOG_WARNING, "rule %s: %c%u@%u was added to IPFIL kernel table",
							    rule->rulename, kipfilp->type, group_number, rulep->rule_number);
					} else {
						if (rulep->bcnt_old != kbcnt) {
							if (rulep->bcnt_old < kbcnt)
								chunk = kbcnt - rulep->bcnt_old;
							else {
								chunk = kipfil_bcnt_max - (rulep->bcnt_old - kbcnt);
								if (maxchunk != 0) {
									if (chunk > maxchunk) {
										syslog(LOG_WARNING, "rule %s: was IPFIL rule %c%u@%u flushed? chunk = %s, maxchunk = %s",
										    rule->rulename, kipfilp->type, group_number, rulep->rule_number,
										    show_bytes(chunk), show_bytes2(maxchunk));
										chunk = kbcnt;
										syslog(LOG_INFO, "rule %s: use absolute value %s of IPFIL %c%u@%u counter",
										    rule->rulename, show_bytes(chunk), kipfilp->type, group_number, rulep->rule_number);
									}
								} else
									syslog(LOG_WARNING, "rule %s: IPFIL %c%u@%u counter was overflowed, old value = %s, current value = %s",
									    rule->rulename, kipfilp->type, group_number, rulep->rule_number, show_bytes(rulep->bcnt_old), show_bytes2(kbcnt));
							}
							rulep->bcnt_old = kbcnt;
							if (rulep->action == ADD) {
								if (add_chunk_to_rule(rule, &chunk) < 0)
									return -1;
							} else /* rulep->action == SUB */
								sub_chunk_from_rule(rule, &chunk);
						}
					}
				}
			}
		if (ri < groupp->nrule) {
			/*
			 * The group or some rules in the group are not
			 * present in the IPFIL kernel table.
			 */
			for (; ri < groupp->nrule; ++rulep, ++ri)
				if (rulep->seen) {
					rulep->seen = 0;
					syslog(LOG_WARNING, "rule %s: %c%u@%u was removed from IPFIL kernel table",
					    rule->rulename, kipfilp->type, group_number, rulep->rule_number);
				} else if (rule->firstcall)
					syslog(LOG_WARNING, "rule %s: %c%u@%u doesn't exist in IPFIL kernel table",
					    rule->rulename, kipfilp->type, group_number, rulep->rule_number);
		}
	}

	if (kipfilp == &kipfil_in) {
		/* Continue accounting for outgoing accounting rules. */
		ipfilacp = &rule->ipfilac_out;
		kipfilp = &kipfil_out;
		goto next_do_ipfilac;
	}

	if (update_db(rule, &rule->bcnt) < 0)
		return -1;
#ifdef WITH_MYSQL
	update_sql_db(rule, &rule->bcnt);
#endif
	return update_rule_limits(rule);
}
#endif /* WITH_IPFIL */

#ifdef WITH_PF
/*
 * Do IP accounting for *rule from Packet Filter table.
 */
static int
do_pfac_for_rule(struct rule *rule)
{
	u_int		i, nr;
	u_quad_t	chunk = 0;	/* initial value isn't used */
	u_quad_t	maxchunk = rule->maxchunk;
	struct pfac	*pfacp = rule->pfac;
	u_quad_t	*kpfp;

	for (i = 0; i < rule->npfac; ++pfacp, ++i) {
		nr = pfacp->number;
		if (nr < nkpf) {
			/* found PF rule in the kernel table */
			kpfp = kpf + nr;
			if (pfacp->seen == 0) {
				pfacp->bcnt_old = *kpfp;
				pfacp->seen = 1;
				if (!rule->firstcall)
					syslog(LOG_WARNING, "rule %s: %u was added to PF kernel table",
					    rule->rulename, nr);
			} else if (pfacp->bcnt_old != *kpfp) {
				if (pfacp->bcnt_old < *kpfp)
					chunk = *kpfp- pfacp->bcnt_old;
				else {
					chunk = UQUAD_MAX - (pfacp->bcnt_old - *kpfp);
					if (maxchunk != 0) {
						if (chunk > maxchunk) {
							syslog(LOG_WARNING, "rule %s: was PF rule %u flushed? chunk = %s, maxchunk = %s",
							    rule->rulename, nr, show_bytes(chunk), show_bytes2(maxchunk));
							chunk = *kpfp;
							syslog(LOG_INFO, "rule %s: use absolute value %s of PF %u counter",
							    rule->rulename, show_bytes(chunk), nr);
						}
					} else
						syslog(LOG_WARNING, "rule %s: PF %u counter was overflowed, old value = %s, current value = %s",
						    rule->rulename, nr, show_bytes(pfacp->bcnt_old), show_bytes2(*kpfp));
				}
				pfacp->bcnt_old = *kpfp;
				if (pfacp->action == ADD) {
					if (add_chunk_to_rule(rule, &chunk) < 0)
						return -1;
				} else /* pfacp->action == SUB */
					sub_chunk_from_rule(rule, &chunk);
			}
		} else {
			if (pfacp->seen != 0) {
				pfacp->seen = 0;
				syslog(LOG_WARNING, "rule %s: %u was removed from PF kernel table",
				    rule->rulename, nr);
			} else if (rule->firstcall)
				syslog(LOG_WARNING, "rule %s: %u doesn't exist in PF kernel table",
				    rule->rulename, nr);
		}
	}
	if (update_db(rule, &rule->bcnt) < 0)
		return -1;
#ifdef WITH_MYSQL
	update_sql_db(rule, &rule->bcnt);
#endif
	return update_rule_limits(rule);
}
#endif /* WITH_PF */

/*
 * This function is called from the do_ipac() function, if the worktime of
 * the rule does not allow accounting.
 */
static void
set_rule_inactive(struct rule *rule)
{
	u_int		i;
#if defined(WITH_IPFW) || defined(WITH_IP6FW)
	struct ipfwac	*fwacp;
#endif
#ifdef WITH_IPFIL
	u_int		j;
	struct ipfilac_group	*groupp;
	struct ipfilac_rule	*rulep;
	struct ipfilac		*ipfilacp;
#endif
#ifdef WITH_PF
	struct pfac	*pfacp;
#endif

#ifdef WITH_IPFW
	for (i = 0, fwacp = rule->ipfwac; i < rule->nipfwac; ++fwacp, ++i)
		fwacp->seen = 0;
#endif
#ifdef WITH_IP6FW
	for (i = 0, fwacp = rule->ip6fwac; i < rule->nip6fwac; ++fwacp, ++i)
		fwacp->seen = 0;
#endif
#ifdef WITH_IPFIL
	ipfilacp = &rule->ipfilac_in;
set_inactive_next_ipfilac:
	for (i = 0, groupp = ipfilacp->group; i < ipfilacp->ngroup; ++groupp, ++i)
		for (j = 0, rulep = groupp->rule; j < groupp->nrule; ++rulep, ++j)
			rulep->seen = 0;
	if (ipfilacp == &rule->ipfilac_in) {
		ipfilacp = &rule->ipfilac_out;
		goto set_inactive_next_ipfilac;
	}
#endif
#ifdef WITH_PF
	for (i = 0, pfacp = rule->pfac; i < rule->npfac; ++pfacp, ++i)
		pfacp->seen = 0;
#endif
	/* Clear bcnt for the rule. */
	rule->bcnt = 0ULL;
	/* Say, that this rule is inactive. */
	rule->is_active = 0;
}

/*
 * This function is called from the do_ipac() function, if the worktime of
 * the rule allows accounting.
 */
static void
set_rule_active(struct rule *rule)
{
	/* Say, that this rule is active. */
	rule->is_active = 1;
	/*
	 * Don't tell anything about found IPFW/IP6FW/IPF/PF rules in
	 * appropriate do_*ac_for_rule() functions.
	 */
	rule->firstcall = 1;
}

/*
 * Make accounting for all rules, check limits, calculate new sleep time.
 */
static int
do_ipac(void)
{
	u_int		rule_sleep_seconds;
	time_t		curr_sec = 0; /* initial value isn't used */
	time_t		wakeup_limits;
	struct rule	*rule;
	struct limit	*limit;
	struct worktime	*wtp;
	struct interval	*intp;

	sleep_seconds = DAY; /* just initial value */
	if (use_worktime)
		curr_sec = curr_tm.tm_hour * HOUR + curr_tm.tm_min * MINUTE + curr_tm.tm_sec;
	SLIST_FOREACH(rule, &rule_head, rule_entry) {
		if (rule->wakeup <= curr_time || (need_rules_check && rule->is_active)) {
			if (rule->use_worktime && rule->wakeup_worktime <= curr_time) {
				wtp = &rule->worktime[curwday];
				if (rule->use_rule_worktime) {
					/* rule { worktime } or global { worktime } */
					if (wtp->interval != NULL) {
						if (rule->worktime_curr_interval < wtp->ninterval) {
							intp = &wtp->interval[rule->worktime_curr_interval];
							if (curr_sec < intp->sec1) {
rule_before_interval:						/* x [   ] */
								set_rule_inactive(rule);
								rule_sleep_seconds = intp->sec1 - curr_sec;
								if (debug_worktime)
									syslog(LOG_INFO, "rule %s: %s left before start of %s %02hu:%02hu-%02hu:%02hu worktime interval",
									    rule->rulename, show_time(rule_sleep_seconds), wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
								rule->wakeup = rule->wakeup_worktime = curr_time + rule_sleep_seconds;
								if (sleep_seconds > rule_sleep_seconds)
									sleep_seconds = rule_sleep_seconds;
								continue;
							} else if (intp->sec1 <= curr_sec && curr_sec < intp->sec2) {
rule_inside_interval:						/* [ x ] */
								if (rule->worktime_curr_interval_flag == 0) {
									/* we were not in this interval before */
									if (append_db(rule, &zero_ULL) < 0)
										return -1;
#ifdef WITH_MYSQL
//									syslog(LOG_ERR, "%s:%d: append_sql_db\n", __FUNCTION__, __LINE__);
									append_sql_db(rule, &zero_ULL);
#endif
									rule->worktime_curr_interval_flag = 1;
									set_rule_active(rule);
									if (debug_worktime)
										syslog(LOG_INFO, "rule %s: new worktime interval",
										    rule->rulename);
								}
								if (debug_worktime)
									syslog(LOG_INFO, "rule %s: %s left before end of %s %02hu:%02hu-%02hu:%02hu worktime interval",
									    rule->rulename, show_time(intp->sec2 - curr_sec), wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
								rule->wakeup_worktime = curr_time + intp->sec2 - curr_sec;
							} else if (rule->worktime_curr_interval_flag) {
								/* [   ] x, but we was in interval. */
								rule->worktime_curr_interval_flag = 0;
								rule->wakeup_worktime = curr_time;
								if (debug_worktime)
									syslog(LOG_INFO, "rule %s: finished %s %02hu:%02hu-%02hu:%02hu worktime interval",
									    rule->rulename, wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
							} else {
								/* [   ] x */
								if (debug_worktime)
									syslog(LOG_INFO, "rule %s: out of %s %02hu:%02hu-%02hu:%02hu worktime interval",
									    rule->rulename, wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
								while (++rule->worktime_curr_interval < wtp->ninterval) {
									/* try to find next interval */
									intp = &wtp->interval[rule->worktime_curr_interval];
									if (curr_sec < intp->sec1)
										/* x [   ] */
										goto rule_before_interval;
									if (intp->sec1 <= curr_sec && curr_sec < intp->sec2)
										/* [ x ] */
										goto rule_inside_interval;
									if (debug_worktime)
										syslog(LOG_INFO, "rule %s: skeeping %s %02hu:%02hu-%02hu:%02hu worktime interval",
										    rule->rulename, wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
								}
								/* cannot find more time intervals for current week day */
								rule->wakeup = rule->wakeup_worktime = curr_time + DAY;
								set_rule_inactive(rule);
								if (debug_worktime)
									syslog(LOG_INFO, "rule %s: cannot find more worktime intervals for %s (current week day)",
									    rule->rulename, wdays[curwday]);
								continue;
							}
						} else {
							/* there is no more time intervals for current week day */
							rule->wakeup = rule->wakeup_worktime = curr_time + DAY;
							set_rule_inactive(rule);
							if (debug_worktime)
								syslog(LOG_INFO, "rule %s: there is no more worktime intervals for %s (current week day)",
								    rule->rulename, wdays[curwday]);
							continue;
						}
					} else {
						/* current week day is not set in worktime */
						rule->wakeup = rule->wakeup_worktime = curr_time + DAY;
						set_rule_inactive(rule);
						if (debug_worktime)
							syslog(LOG_INFO, "rule %s: %s (current week day) is not set in worktime",
							    rule->rulename, wdays[curwday]);
						continue;
					}
				} else
					/* there is not rule { worktime } */
					rule->wakeup_worktime = curr_time + DAY;

				SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
					if (limit->use_worktime && limit->wakeup_worktime <= curr_time) {
						/* limit { worktime } */
						wtp = &limit->worktime[curwday];
						if (wtp->interval != NULL) {
							if (limit->worktime_curr_interval < wtp->ninterval) {
								intp = &wtp->interval[limit->worktime_curr_interval];
								if (curr_sec < intp->sec1)  {
limit_before_interval:							/* x [   ] */
									if (debug_worktime)
										syslog(LOG_INFO, "rule %s, limit %s: %s left before start of %s %02hu:%02hu-%02hu:%02hu worktime interval",
										    rule->rulename, limit->limitname, show_time(intp->sec1 - curr_sec), wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
									limit->wakeup_worktime = curr_time + intp->sec1 - curr_sec;
									limit->is_active = 0;
								} else if (intp->sec1 <= curr_sec && curr_sec < intp->sec2) {
limit_inside_interval:							/* [ x ] */
									if (debug_worktime)
										syslog(LOG_INFO, "rule %s, limit %s: %s left before end of %s %02hu:%02hu-%02hu:%02hu worktime interval",
										    rule->rulename, limit->limitname, show_time(intp->sec2 - curr_sec), wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
									limit->worktime_curr_interval_flag = 1;
									limit->is_active = 1;
									limit->wakeup_worktime = curr_time + intp->sec2 - curr_sec;
								} else if (limit->worktime_curr_interval_flag) {
									/* [   ] x, but we was in interval. */
									limit->worktime_curr_interval_flag = 0;
									limit->wakeup_worktime = curr_time;
									if (debug_worktime)
										syslog(LOG_INFO, "rule %s, limit %s: finished %s %02hu:%02hu-%02hu:%02hu worktime interval",
										    rule->rulename, limit->limitname, wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
								} else {
									/* [   ] x */
									if (debug_worktime)
										syslog(LOG_INFO, "rule %s, limit %s: out of %s %02hu:%02hu-%02hu:%02hu worktime interval",
										    rule->rulename, limit->limitname, wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
									while (++limit->worktime_curr_interval < wtp->ninterval) {
										/* try to find next interval */
										intp = &wtp->interval[limit->worktime_curr_interval];
										if (curr_sec < intp->sec1)
											/* x [   ] */
											goto limit_before_interval;
										if (intp->sec1 <= curr_sec && curr_sec < intp->sec2)
											/* [ x ] */
											goto limit_inside_interval;
										if (debug_worktime)
											syslog(LOG_INFO, "rule %s, limit %s: skeeping %s %02hu:%02hu-%02hu:%02hu worktime interval",
											    rule->rulename, limit->limitname, wdays[curwday], intp->h1, intp->m1, intp->h2, intp->m2);
									}
									/* cannot find more time intervals for current week day */
									limit->is_active = 0;
									limit->wakeup_worktime = curr_time + DAY;
									if (debug_worktime)
										syslog(LOG_INFO, "rule %s, limit %s: cannot find more worktime intervals for %s (current week day)",
										    rule->rulename, limit->limitname, wdays[curwday]);
								}
							} else {
								/* there is no more time intervals for current week day */
								limit->is_active = 0;
								limit->wakeup_worktime = curr_time + DAY;
								if (debug_worktime)
									syslog(LOG_INFO, "rule %s, limit %s: there is no more worktime intervals for %s (current week day)",
									    rule->rulename, limit->limitname, wdays[curwday]);
							}
						} else {
							/* current week day is not set in worktime */
							limit->is_active = 0;
							limit->wakeup_worktime = curr_time + DAY;
							if (debug_worktime)
								syslog(LOG_INFO, "rule %s, limit %s: %s (current week day) is not set in worktime",
								    rule->rulename, limit->limitname, wdays[curwday]);
						}
						if (limit->wakeup_worktime < rule->wakeup_worktime)
							rule->wakeup_worktime = limit->wakeup_worktime;
					}
				}
			}
#ifdef WITH_IPFW
			if (rule->ipfwac != NULL)
				if (do_ipfwac_for_rule(rule) < 0)
					return -1;
#endif
#ifdef WITH_IP6FW
			if (rule->ip6fwac != NULL)
				if (do_ip6fwac_for_rule(rule) < 0)
					return -1;
#endif
#ifdef WITH_IPFIL
			if (rule->ipfilac_in.group != NULL ||
			    rule->ipfilac_out.group != NULL)
				if (do_ipfilac_for_rule(rule) < 0)
					return -1;
#endif
#ifdef WITH_PF
			if (rule->pfac != NULL)
				if (do_pfac_for_rule(rule) < 0)
					return -1;
#endif
			rule->wakeup = curr_time + rule->update_db_time;
			if (rule->append_db_time != 0) {
				if (rule->newrec_time <= curr_time && curr_tm.tm_hour != 24) {
					/* append new record, but do not append it at the end of day */
					if (append_db(rule, &zero_ULL) < 0)
						return -1;
#ifdef WITH_MYSQL
//					syslog(LOG_ERR, "%s:%d: append_sql_db\n", __FUNCTION__, __LINE__);
                                           append_sql_db(rule, &zero_ULL);
#endif
					rule->bcnt = 0;
				}
				if (rule->wakeup > rule->newrec_time)
					rule->wakeup = rule->newrec_time;
			}
			if (!SLIST_EMPTY(&rule->limit_head) && curr_tm.tm_hour != 24) {
				if (check_rule_limits(rule, &wakeup_limits) < 0)
					return -1;
				if (rule->wakeup > wakeup_limits)
					rule->wakeup = wakeup_limits;
			}
			if (rule->use_worktime && rule->wakeup > rule->wakeup_worktime)
				rule->wakeup = rule->wakeup_worktime;
			rule_sleep_seconds = rule->wakeup - curr_time;
			if (sleep_seconds > rule_sleep_seconds)
				sleep_seconds = rule_sleep_seconds;
			if (debug_time > 1)
				syslog(LOG_INFO, "do_ipac: rule %s, new sleep = %u sec.", rule->rulename, rule_sleep_seconds);
		} else {
			rule_sleep_seconds = rule->wakeup - curr_time;
			if (sleep_seconds > rule_sleep_seconds)
				sleep_seconds = rule_sleep_seconds;
			if (debug_time > 1)
				syslog(LOG_INFO, "do_ipac: rule %s, rest sleep = %u sec.", rule->rulename, rule_sleep_seconds);
		}
		rule->firstcall = 0;
	}
	need_rules_check = 0;

#if 0
	SLIST_FOREACH(rule, &rule_head, rule_entry) {
	struct ipfwac	*fwacp = rule->ipfwac;
		kipfw_zero_table(fwacp->number);
	}
#endif
	return 0;
}

static int
do_ipac_limits(void)
{
	time_t		wakeup_limits;
	struct rule	*rule;

	SLIST_FOREACH(rule, &rule_head, rule_entry)
		if (rule->is_active) {
			if (!SLIST_EMPTY(&rule->limit_head)) {
				if (check_rule_limits(rule, &wakeup_limits) < 0)
					return -1;
				if (rule->wakeup > wakeup_limits)
					rule->wakeup = wakeup_limits;
			}
		}
	return 0;
}

/*
 * New day came, close old database files if needed, else open new ones.
 */
static int
newday_came(void)
{
	int		curr_year = curr_tm.tm_year + 1900,
			curr_mon = curr_tm.tm_mon + 1;
	char		*path;
	struct rule	*rule;
	struct limit	*limit;

	SLIST_FOREACH(rule, &rule_head, rule_entry) {
		rule->bcnt = 0ULL; /* flush counter */

		if (rule->use_worktime) {
			/* Reinit pointers to current worktime intervals. */
			rule->worktime_curr_interval = 0;
			rule->worktime_curr_interval_flag = 0;
			/*
			 * Make the rule wakeup immediately in do_ipac() and
			 * calculate wakeup and wakeup_worktime values there.
			 */
			rule->wakeup = rule->wakeup_worktime = 0;
			SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
				/* Do the same for each limit. */
				limit->worktime_curr_interval = 0;
				limit->worktime_curr_interval_flag = 0;
				limit->wakeup_worktime = 0;
			}
		}

		if (process_mon == curr_mon && process_year == curr_year) {
			/* New day came, but it is the same month now. */
			if (!rule->use_rule_worktime) {
				/*
				 * Worktime parameter is not used, just
				 * add a new entry with 0 bytes for a new day.
				 */
				if (append_db(rule, &zero_ULL) < 0)
					return -1;
#ifdef WITH_MYSQL
//				syslog(LOG_ERR, "%s:%d: append_sql_db\n", __FUNCTION__, __LINE__);
				append_sql_db(rule, &zero_ULL);
#endif
			}
			continue;
		}
		/* The new month came. */
		if (rule->fp != NULL) {
			/* close file for previous month */
			if (fclose(rule->fp) != 0) {
				syslog(LOG_ERR, "fclose(%s): %m", rule->filename);
				return -1;
			}
			free(rule->filename);
		}
		if (asprintf(&path, "%s/%s/%d", db_dir, rule->rulename, curr_year) < 0) {
			syslog(LOG_ERR, "asprintf: %m");
			return -1;
		}
		switch (check_db_dir(path, rule)) {
		case 1:	/* dir is present */
			break;
		case 0: /* no such dir */
			/* create directory DBDIR/<rule>/YYYY */
			if (create_db_dir(path, rule) < 0)
				return -1;
			break;
		default: /* -1, error */
			return -1;
		}
		free(path);

		if (asprintf(&path, "%s/%s/%d/%02d", db_dir, rule->rulename, curr_year, curr_mon) < 0) {
			syslog(LOG_ERR, "asprintf: %m");
			return -1;
		}
		switch (check_db_file(path, rule)) {
		case 1: /* The file exists. */
			if (process_year != 0)
				/* Do not say following warning just after start. */
				syslog(LOG_WARNING, "new month %d/%02d came, but file %s for it already exists",
				    curr_year, curr_mon, path);
			if ( (rule->fp = fopen(path, "r+")) == NULL) {
				syslog(LOG_ERR, "fopen(%s, \"r+\"): %m", path);
				return -1;
			}
			break;
		case 0: /* The file does not exist. */
			if ( (rule->fp = create_db_file(path, rule)) == NULL)
				return -1;
			break;
		default: /* -1, error */
			return -1;
		}
		rule->fd = fileno(rule->fp);
		rule->filename = path;
		if (!rule->use_rule_worktime && append_db(rule, &zero_ULL) < 0)
			return -1;
#ifdef WITH_MYSQL
		if (!rule->use_rule_worktime){
//			syslog(LOG_ERR, "%s:%d: append_sql_db\n", __FUNCTION__, __LINE__);
			append_sql_db(rule, &zero_ULL);
		}
#endif
	}
	process_mon = curr_tm.tm_mon + 1;
	process_year = curr_tm.tm_year + 1900;
	/* get time UTC of new day in seconds */
	newday_time = mk_time_exp_upto(curr_time, UPTO_DAY);
	return 0;
}

/*
 * The main function for accounting, is called from main().
 */
int
run_ipac(void)
{
	time_t		new_curr_time;
	struct tm	new_curr_tm;
	sigset_t	sigmask, zeromask, pendmask;
	struct rule	*rule;

	sigemptyset(&zeromask);
	sigemptyset(&sigmask);

	if (debug)
		sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGTERM);
	sigaddset(&sigmask, SIGHUP);
	sigaddset(&sigmask, SIGCHLD);
	sigaddset(&sigmask, SIGUSR1);

	if (sigprocmask(SIG_BLOCK, &sigmask, (sigset_t *)NULL) < 0) {
		syslog(LOG_ERR, "sigprocmask(SIG_BLOCK): %m");
		return -1;
	}
	/*
	 * XXX: signals SIGTERM (and SIGINT), SIGHUP, SIGUSR1 before function
	 *      sigprocmask() are not handled safe.
	 */
run_ipac_start:
	syslog(LOG_INFO, "make IP accounting...");
	SLIST_INIT(&wpid_head);

	if (newday_came() < 0)
		return -1;
	for (;;) {
#ifdef WITH_IPFW
		if (use_ipfw)
			if (kipfw_read_table() < 0)
				return -1;
#endif
#ifdef WITH_IP6FW
		if (use_ip6fw)
			if (kip6fw_read_table() < 0)
				return -1;
#endif
#ifdef WITH_IPFIL
		if (use_ipfil)
			if (kipfil_read_tables() < 0)
				return -1;
#endif
#ifdef WITH_PF
		if (use_pf)
			if (kpf_read_table() < 0)
				return -1;
#endif

		if (time(&new_curr_time) == (time_t)-1) {
			syslog(LOG_ERR, "time: %m");
			return -1;
		}
		localtime_r(&new_curr_time, &new_curr_tm);

		/* 
		 * Check for problems with time and local date,
		 * XXX: if TZ is changed outside, this fact isn't reflected
		 *	on running process [is it bug of system or is it a standard?].
		 */
		if (new_curr_time < curr_time) {
			syslog(LOG_WARNING, "UTC goes back with delta %.0f seconds",
			    difftime(new_curr_time, curr_time));
			time_changed_flag = 1;
		}
		if ((curr_tm.tm_zone != NULL && new_curr_tm.tm_zone == NULL) ||
		    (curr_tm.tm_zone == NULL && new_curr_tm.tm_zone != NULL) ||
		    (curr_tm.tm_zone != NULL && new_curr_tm.tm_zone != NULL &&
		     strcmp(curr_tm.tm_zone, new_curr_tm.tm_zone) != 0)) {
			syslog(LOG_WARNING, "time zone was changed, old TZ = %s, new TZ = %s",
			    curr_tm.tm_zone != NULL ? curr_tm.tm_zone : "???",
			    new_curr_tm.tm_zone != NULL ? new_curr_tm.tm_zone : "???");
			time_changed_flag = 1;
		}
		if (curr_tm.tm_gmtoff != new_curr_tm.tm_gmtoff) {
			syslog(LOG_WARNING, "offset from UTC was changed, old gmtoff = %lds, new gmtoff = %lds (delta = %s%s)",
			    curr_tm.tm_gmtoff, new_curr_tm.tm_gmtoff,
			    curr_tm.tm_gmtoff > new_curr_tm.tm_gmtoff ? "+" : "-",
			    curr_tm.tm_gmtoff > new_curr_tm.tm_gmtoff ? show_time(curr_tm.tm_gmtoff - new_curr_tm.tm_gmtoff) : show_time(new_curr_tm.tm_gmtoff - curr_tm.tm_gmtoff));
			time_changed_flag = 1;
		}
		if (curr_tm.tm_isdst != new_curr_tm.tm_isdst) {
			syslog(LOG_WARNING, "\"summer time in effect\" was changed, old isdst = %s, new isdst = %s",
			    curr_tm.tm_isdst ? "yes" : "no", new_curr_tm.tm_isdst ? "yes" : "no");
			time_changed_flag = 1;
		}
		if (tmcmp(&new_curr_tm, &curr_tm) < 0) {
			syslog(LOG_WARNING, "local time goes back, old localtime = %d.%02d.%02d/%02d:%02d:%02d (%s), new localtime = %d.%02d.%02d/%02d:%02d:%02d (%s)",
			    curr_tm.tm_year + 1900, curr_tm.tm_mon + 1, curr_tm.tm_mday, curr_tm.tm_hour, curr_tm.tm_min, curr_tm.tm_sec,
			    curr_tm.tm_zone != NULL ? curr_tm.tm_zone : "???",
			    new_curr_tm.tm_year + 1900, new_curr_tm.tm_mon + 1, new_curr_tm.tm_mday, new_curr_tm.tm_hour, new_curr_tm.tm_min, new_curr_tm.tm_sec,
			    new_curr_tm.tm_zone != NULL ? new_curr_tm.tm_zone : "???");
			time_changed_flag = 1;
		}

		if (time_changed_flag) {
			syslog(LOG_WARNING, "unsuccessive date or time changes are detected");
time_changed:
			syslog(LOG_WARNING, "dumping all statistics with old timestamps...");
			/* 
			 * XXX store new accounting with old timestamp,
			 *     curr_tm isn't changed and is equal to old curr_tm.
			 */
			need_rules_check = 1;
			if (do_ipac() < 0)
				return -1;
			syslog(LOG_WARNING, "append new records for all rules");
			curr_time = new_curr_time;
			curr_tm = new_curr_tm;
			curwday = curr_tm.tm_wday;
			process_mon = process_year = 0;
			if (newday_came() < 0)
				return -1;
			if (init_limits(0) < 0)
				return -1;
			time_changed_flag = 0;
			continue;
		}

		if (new_curr_time >= newday_time) {
			if (new_curr_time - newday_time > DAY) {
				syslog(LOG_WARNING, "time changed too quickly (delta %.0f seconds is greater that 1 day)",
				    difftime(new_curr_time, newday_time));
				goto time_changed;
			}
			if (new_curr_tm.tm_mday != curr_tm.tm_mday) {
				need_rules_check = 1;
				/* update record at the end of day with
				   second timestamp equal to 24:00:00 */
				curr_tm.tm_hour = 24;
				curr_tm.tm_min = curr_tm.tm_sec = 0;
				curr_time = newday_time;
				if (do_ipac() < 0)
					return -1;
				curr_tm = new_curr_tm;
				/* some time can be spent in do_ipac(), so we should
                                   set first timestamp of new day as 00:00:00, this isn't
				   correct but will not confused user runs ipastat(8) with
				   the -t switch */
				curr_tm.tm_hour = curr_tm.tm_min = curr_tm.tm_sec = 0;
				curwday = curr_tm.tm_wday;
				if (do_ipac_limits() < 0)
					return -1;
				curr_time = new_curr_time;
				if (newday_came() < 0)
					return -1;
			} else
				syslog(LOG_WARNING, "new day did not come, but was expected");
			curr_time = new_curr_time;
			curr_tm = new_curr_tm;
			process_mon = curr_tm.tm_mon + 1;
			process_year = curr_tm.tm_year + 1900;
			/* get time UTC of new day in seconds */
			new_curr_tm.tm_hour = new_curr_tm.tm_min = new_curr_tm.tm_sec = 0;
			newday_time = mktime(&new_curr_tm) + DAY; 
		} else {
			curr_time = new_curr_time;
			curr_tm = new_curr_tm;
		}
		if (goingdown_flag){
#if 1
//	struct rule	*rule;
	SLIST_FOREACH(rule, &rule_head, rule_entry) {
	struct ipfwac	*fwacp = rule->ipfwac;
//		syslog(LOG_ERR, "zero!!! %d\n", fwacp->number);
		kipfw_zero_table(fwacp->number);
	}
#endif

		}

		if (do_ipac() < 0)
			return -1;
		if (goingdown_flag)
			return 0;
		if (reconfigure_flag) {
			switch (do_reconfigure()) {
			case 0:
				/* configuration file was successfuly parsed */
				reconfigure_flag = 0;
				goto run_ipac_start;
				/* NOTREACHED */
			case -1:
				/* configuration file was successful parsed,
				   but k*_init() failed */
				return -1;
			/* do_reconfigure() also returns -2, which means that
			   there are problems with configuration file(s)
			   parsing */
			}
			reconfigure_flag = 0;
		}
		if (db_dump_flag) {
			syslog(LOG_INFO, "accounting information was successfuly dumped to database");
			db_dump_flag = 0;
		}

		if (sleep_seconds + curr_time > newday_time)
			sleep_seconds = newday_time - curr_time;

		if (debug_time > 0)
			syslog(LOG_INFO, "run_ipac: sleep_seconds = %u sec.", sleep_seconds);

		if (sleep_seconds != 0) {
			alarm(sleep_seconds);	/* set alarm */
			while (wakeup_flag == 0)
				sigsuspend(&zeromask);
			alarm(0);		/* release alarm */
		} else {
			/* should not set alarm, also signals INT, TERM, HUP,
			   CHLD and USR1 should be tested */
			if (sigpending(&pendmask) < 0) {
				syslog(LOG_ERR, "sigpending: %m");
				return -1;
			}
			if (sigismember(&pendmask, SIGTERM) ||
			    sigismember(&pendmask, SIGHUP) ||
			    sigismember(&pendmask, SIGCHLD) ||
			    sigismember(&pendmask, SIGUSR1) ||
			    (debug && sigismember(&pendmask, SIGINT)))
				sigsuspend(&zeromask);	/* should be interrupted immediately */
		}
		if (child_terminated_flag) {
			check_childs();
			child_terminated_flag = 0;
		}
		if (reconfigure_flag)
			syslog(LOG_WARNING, "caught signal %d '%s', reconfiguring...",
			    SIGHUP, sys_signame[SIGHUP]);
		if (db_dump_flag)
			syslog(LOG_INFO, "caught signal %d '%s', dumping database...",
			    SIGUSR1, sys_signame[SIGUSR1]);
		if (goingdown_flag)
			syslog(LOG_INFO, "caught signal %d '%s', shutdowning...",
			    goingdown_flag, sys_signame[goingdown_flag]);
		wakeup_flag = 0;
	}
}

/*
 * Append new time stamp in limit file.
 */
static int
append_limit_ts(const struct limit *limit, char type, const struct tm *tm_ptr)
{
	if (fseek(limit->fp, 0L, SEEK_END) < 0) {
		syslog(LOG_ERR, "fseek(%s, 0, SEEK_END): %m", limit->limitname);
		return -1;
	}
	if (fprintf(limit->fp, "%c %d.%02d.%02d/%02d:%02d:%02d\n", type,
	    tm_ptr->tm_year + 1900, tm_ptr->tm_mon + 1, tm_ptr->tm_mday,
	    tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec) < LIMIT_TIMESTAMP_SIZE) {
		syslog(LOG_ERR, "fprintf(%s): %m", limit->limitname);
		return -1;
	}
	if (fflush(limit->fp) != 0) {
		syslog(LOG_ERR, "fflush(%s): %m", limit->filename);
		return -1;
	}
	return 0;
}

/*
 * SIGCHLD signal handler.
 */
void
sig_chld(int signo)
{
	child_terminated_flag = wakeup_flag = 1;
}

/*
 * SIGINT and/or SIGTERM signal(s) handler.
 */
void
end_work(int signo)
{
	need_rules_check = wakeup_flag = 1;
	goingdown_flag = signo;
}

/*
 * SIGALRM signal handler, can be caught from alarm() in run_ipac().
 */
void
sig_alrm(int signo)
{
	wakeup_flag = 1;
}

/*
 * SIGUSR1 signal handler.
 */
void
force_db_dump(int signo)
{
	db_dump_flag = need_rules_check = wakeup_flag = 1;
}

/*
 * SIGHUP signal handler, cause reconfiguring.
 */
void
reconfigure(int signo)
{
	reconfigure_flag = need_rules_check = wakeup_flag = 1;
}

/*
 * Release memory held by fields of *rule struct.
 */
static int
free_rule_struct(struct rule *rule)
{
	u_int		i;
	struct limit	*limit1;
#ifdef WITH_IPFIL
	struct ipfilac		*ipfilacp;
	struct ipfilac_group	*groupp;
#endif /* WITH_IPFIL */

	free(rule->rulename);
	if (rule->fp != NULL)
		if (fclose(rule->fp) != 0) {
			syslog(LOG_ERR, "fclose(%s): %m", rule->filename);
			return -1;
		}
	free(rule->filename);
#ifdef WITH_IPFW
	free(rule->ipfwac);
#endif

#ifdef WITH_IP6FW
	free(rule->ip6fwac);
#endif

#ifdef WITH_IPFIL
	ipfilacp = &rule->ipfilac_in;
free_next_ipfilac:
	for (i = 0, groupp = ipfilacp->group; i < ipfilacp->ngroup; ++groupp, ++i)
		free(groupp->rule);
	free(ipfilacp->group);
	if (ipfilacp == &rule->ipfilac_in) {
		ipfilacp = &rule->ipfilac_out;
		goto free_next_ipfilac;
	}
#endif /* WITH_IPFIL */

#ifdef WITH_PF
	free(rule->pfac);
#endif
	for (i = 0; i < 7; ++i)
		free(rule->worktime[i].interval);

	while (!SLIST_EMPTY(&rule->limit_head)) {
		limit1 = SLIST_FIRST(&rule->limit_head);
		SLIST_REMOVE_HEAD(&rule->limit_head, limit_entry);
		free(limit1->limitname);
		if (limit1->fp != NULL) {
			if (fclose(limit1->fp) != 0) {
				syslog(LOG_ERR, "fclose(%s): %m", limit1->filename);
				return -1;
			}
			free(limit1->filename);
		}
		free_cmd_list(limit1->reach.cmd, limit1->reach.ncmd);
		free_cmd_list(limit1->expire.cmd, limit1->expire.ncmd);
		free_commands(&limit1->rc[0]);
		free_commands(&limit1->rc[1]);
		for (i = 0; i < 7; ++i)
			free(limit1->worktime[i].interval);
		free(limit1);
	}
	free_commands(&rule->rc[0]);
	free_commands(&rule->rc[1]);
	return 0;
}

/*
 * Release memory held by all rule structs pointed by *head.
 */
static int
free_rule_list(struct rule_slisthead *headp)
{
	struct rule *rule1;

	while (!SLIST_EMPTY(headp)) {
		rule1 = SLIST_FIRST(headp);
		SLIST_REMOVE_HEAD(headp, rule_entry);
		if (free_rule_struct(rule1) < 0)
			return -1;
		free(rule1);
	}
	return 0;
}

/*
 * Reread configuration file, parse it and if it is correct, then use
 * new settings.
 */
static int
do_reconfigure(void)
{
	struct rule_slisthead	BACKUP_VAR(rule_head);
#ifdef WITH_IPFW
	int		BACKUP_VAR(use_ipfw);
#endif
#ifdef WITH_IP6FW
	int		BACKUP_VAR(use_ip6fw);
#endif
#ifdef WITH_IPFIL
	int		BACKUP_VAR(use_ipfil);
	int		BACKUP_VAR(use_ipfil_in);
	int		BACKUP_VAR(use_ipfil_out);
#endif /* WITH_IPFIL */
#ifdef WITH_PF
	int		BACKUP_VAR(use_pf);
#endif
	int		BACKUP_VAR(use_worktime);
	struct commands	BACKUP_VAR(shutdown_global);
	int	lock_db_bkp = lock_db;
	u_int	lock_wait_time_bkp = lock_wait_time;
	char	*db_dir_bkp = db_dir;

	backup_debug();

	syslog(LOG_INFO, "rereading configuration file...");

	if (parse_config(RECONFIG_PARSING) < 0) {
		syslog(LOG_WARNING, "continue using previous configuration");
		if (free_rule_list(&rule_head) < 0)
			return -1;
		restore_debug();
		RESTORE_VAR(rule_head);
		RESTORE_VAR(use_worktime);
		RESTORE_VAR(shutdown_global);
#ifdef WITH_IPFW
		RESTORE_VAR(use_ipfw);
#endif
#ifdef WITH_IP6FW
		RESTORE_VAR(use_ip6fw);
#endif
#ifdef WITH_IPFIL
		RESTORE_VAR(use_ipfil);
		RESTORE_VAR(use_ipfil_in);
		RESTORE_VAR(use_ipfil_out);
#endif
#ifdef WITH_PF
		RESTORE_VAR(use_pf);
#endif
		db_dir = db_dir_bkp;
		lock_db = lock_db_bkp;
		lock_wait_time = lock_wait_time_bkp;
		return -2;
	}

#ifdef WITH_IPFW
	if (BACKUP_VAR_NAME(use_ipfw) && !use_ipfw)
		kipfw_close();
	else if (!BACKUP_VAR_NAME(use_ipfw) && use_ipfw)
		if (kipfw_init() < 0)
			return -1;
#endif

#ifdef WITH_IP6FW
	if (BACKUP_VAR_NAME(use_ip6fw) && !use_ip6fw)
		kip6fw_close();
	else if (!BACKUP_VAR_NAME(use_ip6fw) && use_ip6fw)
		if (kip6fw_init() < 0)
			return -1;
#endif

#ifdef WITH_IPFIL
	if (BACKUP_VAR_NAME(use_ipfil) && !use_ipfil)
		kipfil_close();
	else if (!BACKUP_VAR_NAME(use_ipfil) && use_ipfil)
		if (kipfil_init() < 0)
			return -1;
#endif

#ifdef WITH_PF
	if (BACKUP_VAR_NAME(use_pf) && !use_pf)
		kpf_close();
	else if (!BACKUP_VAR_NAME(use_pf) && use_pf)
		if (kpf_init() < 0)
			return -1;
#endif

	syslog(LOG_INFO, "use new configuration");
	if (free_rule_list(&BACKUP_VAR_NAME(rule_head)) < 0)
		return -1;
	free_cmd_list(shutdown_global_bkp.cmd, shutdown_global_bkp.ncmd);
	if (db_dir_bkp != db_dir_default)
		free(db_dir_bkp);
	process_mon = process_year = 0;

#ifdef WITH_MYSQL
       if (init_sql_db() < 0){
       syslog(LOG_ERR, "MySQL reconfigure filed :-(( continue fork...");
/*             return -1;      */
       }
#endif
	return init_db();
}


/*
 * Update byte counters of limits for *rule.
 */
static int
update_rule_limits(const struct rule *rule)
{
	struct limit	*limit;

	SLIST_FOREACH(limit, &rule->limit_head, limit_entry)
		if (limit->is_changed) {
			if (fseek(limit->fp, 0L, SEEK_SET) < 0) {
				syslog(LOG_ERR, "fseek(%s, 0, SEEK_SET): %m", limit->filename);
				return -1;
			}
			if (lock_db_file_until_end(limit->filename, limit->fd, SEEK_SET) < 0)
				return -1;
			if (fprintf(limit->fp, "%020qu", limit->bcnt) != LIMIT_COUNTER_SIZE) {
				syslog(LOG_ERR, "fprintf(%s, \"%%020qu\"), failed: %m", limit->filename);
				return -1;
			}
			if (fflush(limit->fp) != 0) {
				syslog(LOG_ERR, "fflush(%s): %m", limit->filename);
				return -1;
			}
			if (unlock_db_file(limit->filename, limit->fd) < 0)
				return -1;
			limit->is_changed = 0;
		}
	return 0;
}

/*
 * Add chunk bytes to every not reached and active limit of *rule.
 */
static void
add_chunk_to_rule_limits(const struct rule *rule, const u_quad_t *chunk_ptr)
{
	u_quad_t	chunk;
	struct limit	*limit;

	SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
		if ((limit->status & LIMIT_IS_REACHED) || !limit->is_active)
			continue;
		chunk = *chunk_ptr;
		if (limit->bcnt_sub >= chunk)
			limit->bcnt_sub -= chunk;
		else {
			chunk -= limit->bcnt_sub;
			limit->bcnt_sub = 0;
			if (limit->bcnt <= UQUAD_MAX - chunk)
				limit->bcnt += chunk;
			else {
				limit->bcnt = UQUAD_MAX;
				syslog(LOG_WARNING, "rule %s, limit %s: byte counter overflowed",
				    rule->rulename, limit->limitname);
			}
			limit->is_changed = 1;
		}
	}
}

/*
 * Subtract chunk bytes from every not reached and active limit of *rule.
 */
static void
sub_chunk_from_rule_limits(const struct rule *rule, const u_quad_t *chunk_ptr)
{
	struct limit	*limit;

	SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
		if ((limit->status & LIMIT_IS_REACHED) || !limit->is_active)
			continue;
		if (limit->bcnt >= *chunk_ptr)
			limit->bcnt -= *chunk_ptr;
		else {
			if (limit->bcnt_sub <= UQUAD_MAX - (*chunk_ptr - limit->bcnt))
				limit->bcnt_sub += *chunk_ptr - limit->bcnt;
			else {
				syslog(LOG_WARNING, "rule %s, limit %s: wrong configuration for some accounting rule: \"subtracted\" counter overflowed",
				    rule->rulename, limit->limitname);
				limit->bcnt_sub = UQUAD_MAX;
			}
			limit->bcnt = 0;
		}
		limit->is_changed = 1;
	}
}

/*
 * Run commands in "startup" and "shutdown" sections in "rule" sections.
 * If x == 0 then run commands from "startup" sections, else from
 * "shutdown" ones.
 */
int
run_rules_rc(int x)
{
	int		limit_is_reached;
	char		*msg = x == 0 ? "startup" : "shutdown";
	struct rule	*rule;
	struct limit	*limit;
	
	SLIST_FOREACH(rule, &rule_head, rule_entry) {
		if (rule->rc[x].cmd != NULL) {
			syslog(LOG_INFO, "rule %s (%s): run commands", rule->rulename, msg);
			if (exec_cmd_list(rule->rc[x].cmd, rule->rc[x].ncmd,
			    "rule %s (%s)", rule->rulename, msg) < 0)
				return -1;
		}
		limit_is_reached = 0;
		if (rule->rc[x].cmd_if_limit != NULL || rule->rc[x].cmd_if_nolimit != NULL) {
			limit_is_reached = 0;
			SLIST_FOREACH(limit, &rule->limit_head, limit_entry)
				if (limit->status & LIMIT_IS_REACHED) {
					limit_is_reached = 1;
					break;
				}
			if (limit_is_reached && rule->rc[x].cmd_if_limit != NULL) {
				syslog(LOG_INFO, "rule %s (%s, if_limit): run commands", rule->rulename, msg);
				if (exec_cmd_list(rule->rc[x].cmd_if_limit, rule->rc[x].ncmd_if_limit,
				    "rule %s (%s, if_limit)", rule->rulename, msg) < 0)
					return -1;
			} else if (!limit_is_reached && rule->rc[x].cmd_if_nolimit != NULL) {
				syslog(LOG_INFO, "rule %s (%s, if_nolimit): run commands",
				    rule->rulename, msg);
				if (exec_cmd_list(rule->rc[x].cmd_if_nolimit, rule->rc[x].ncmd_if_nolimit,
				    "rule %s (%s, if_nolimit)", rule->rulename, msg) < 0)
					return -1;
			}
		}
		SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
			if (limit->rc[x].cmd != NULL) {
				syslog(LOG_INFO, "rule %s, limit %s (%s): run commands",
				    rule->rulename, limit->limitname, msg);
				if (exec_cmd_list(limit->rc[x].cmd, limit->rc[x].ncmd,
				    "rule %s, limit %s (%s)", rule->rulename, limit->limitname, msg) < 0)
					return -1;
			}
			if (limit->status & LIMIT_IS_REACHED) {
				if (limit->rc[x].cmd_if_limit != NULL) {
					syslog(LOG_INFO, "rule %s, limit %s (%s, if_limit): run commands",
					    rule->rulename, limit->limitname, msg);
					if (exec_cmd_list(limit->rc[x].cmd_if_limit, limit->rc[x].ncmd_if_limit,
					    "rule %s, limit %s (%s, if_limit)", rule->rulename, limit->limitname, msg) < 0)
						return -1;
				}
			} else if (limit->rc[x].cmd_if_nolimit != NULL) {
				syslog(LOG_INFO, "rule %s, limit %s (%s, if_nolimit): run commands",
				    rule->rulename, limit->limitname, msg);
				if (exec_cmd_list(limit->rc[x].cmd_if_nolimit, limit->rc[x].ncmd_if_nolimit,
				    "rule %s, limit %s (%s, if_nolimit)", rule->rulename, limit->limitname, msg) < 0)
					return -1;
			}
		}
	}
	return 0;
}

/*
 * This routine implemets "limit" section(s).
 */
static int
check_rule_limits(const struct rule *rule, time_t *wakeup)
{
	struct limit *limit;

	*wakeup = curr_time + DAY; /* just initial value */
	SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
		if (!limit->is_active)
			continue;
		if (limit->status & LIMIT_IS_REACHED) {
			/* limit has been already reached */
			if (limit->status & LIMIT_EXEC)
				continue; /* some commands are run in background */
			if (limit->expire.time.upto != UPTO_NOTSET) {
				/* "expire" section is used */
				if (!(limit->status & LIMIT_EXPIRE_CHECKED)) {
					/* first time we come here */
					if (lock_db_file_until_end(limit->filename, limit->fd, SEEK_SET) < 0)
						return -1;
					if (append_limit_e_ts(limit) < 0)
						return -1;
					if (unlock_db_file(limit->filename, limit->fd) < 0)
						return -1;
					limit->status |= LIMIT_EXPIRE_CHECKED;
					if (*wakeup > limit->expire_time)
						*wakeup = limit->expire_time;
				} else if (limit->expire_time <= curr_time) {
					/* it's time to expire limit */
					if (limit->expire.cmd != NULL && !(limit->status & LIMIT_EXPIRE_EXEC)) {
						/* "exec" parameter in the "expire" section is used and
						    we haven't run any command from the "expire" section yet */
						if (debug_limit > 0)
							syslog(LOG_INFO, "rule %s, limit %s: limit expired",
							    rule->rulename, limit->limitname);
						if (debug_exec > 0)
							syslog(LOG_INFO, "rule %s, limit %s (expire): run commands",
							    rule->rulename, limit->limitname);
						if ( (limit->wpid = exec_cmd_list_bg(limit->expire.cmd, limit->expire.ncmd, "rule %s, limit %s (expire)",
						    rule->rulename, limit->limitname)) < 0)
							return -1;
						SLIST_INSERT_HEAD(&wpid_head, limit, wpid_entry);
						if (lock_db_file_until_end(limit->filename, limit->fd, SEEK_SET) < 0)
							return -1;
						if (append_limit_ts(limit, LIMIT_EXECUTED, &curr_tm) < 0)
							return -1;
						if (unlock_db_file(limit->filename, limit->fd) < 0)
							return -1;
						limit->status |= LIMIT_EXPIRE_EXEC | LIMIT_EXEC;
					} else if (limit->expire.cmd == NULL ||
						   (limit->expire.cmd != NULL && (limit->status & LIMIT_EXPIRE_EXEC))) {
						/* "exec" parameters in "expire" section are not used,
						   or are used, but commands already have been executed */
						if (limit->expire.cmd == NULL && debug_limit > 0)
							syslog(LOG_INFO, "rule %s, limit %s: limit expired",
							    rule->rulename, limit->limitname);
						if (lock_db_file_until_end(limit->filename, limit->fd, SEEK_SET) < 0)
							return -1;
						if (restart_limit(limit) < 0)
							return -1;
						if (unlock_db_file(limit->filename, limit->fd) < 0)
							return -1;
						if (limit->zero_time_param.upto != UPTO_NOTSET)
							if (*wakeup > limit->zero_time)
								*wakeup = limit->zero_time;
						limit->status = 0;
					}
				} else {
					/* just check time to expire */
					if (*wakeup > limit->expire_time)
						*wakeup = limit->expire_time;
				}
			}
		} else {
			/* limit hasn't been reached before */
			if (limit->bcnt >= limit->byte_limit) {
				/* limit has just been reached */
				if (debug_limit > 0)
					syslog(LOG_INFO, "rule %s, limit %s: limit reached, bcnt = %s",
					    rule->rulename, limit->limitname, show_bytes(limit->bcnt));
				limit->status = LIMIT_IS_REACHED;
				limit->reach_time = curr_time;
				if (lock_db_file_until_end(limit->filename, limit->fd, SEEK_SET) < 0)
					return -1;
				if (append_limit_ts(limit, LIMIT_REACHED, &curr_tm) < 0)
					return -1;
				if (limit->reach.cmd != NULL) {
					/* "exec" parameter in "reach" section is used */
					if (debug_exec > 0)
						syslog(LOG_INFO, "rule %s, limit %s (reach): run commands", 
						    rule->rulename, limit->limitname);
					if ( (limit->wpid = exec_cmd_list_bg(limit->reach.cmd, limit->reach.ncmd, "rule %s, limit %s (reach)",
					    rule->rulename, limit->limitname)) < 0)
						return -1;
					SLIST_INSERT_HEAD(&wpid_head, limit, wpid_entry);
					if (append_limit_ts(limit, LIMIT_EXECUTED, &curr_tm) < 0)
						return -1;
					limit->status |= LIMIT_EXEC;
				} else if (limit->expire.time.upto != UPTO_NOTSET) {
					if (append_limit_e_ts(limit) < 0)
						return -1;
					limit->status |= LIMIT_EXPIRE_CHECKED;
					if (*wakeup > limit->expire_time)
						*wakeup = limit->expire_time;
				}
				if (unlock_db_file(limit->filename, limit->fd) < 0)
					return -1;
			} else if (limit->zero_time_param.upto != UPTO_NOTSET) {
				/* "zero_time" parameter in "limit" section is used */
				if (limit->zero_time <= curr_time) {
					/* it is time to restart limit */
					if (debug_limit > 0)
						syslog(LOG_INFO, "rule %s, limit %s: limit zeroed",
						    rule->rulename, limit->limitname);
					if (lock_db_file_until_end(limit->filename, limit->fd, SEEK_SET) < 0)
						return -1;
					if (restart_limit(limit) < 0)
						return -1;
					if (unlock_db_file(limit->filename, limit->fd) < 0)
						return -1;
				}
				if (*wakeup > limit->zero_time)
					*wakeup = limit->zero_time;
			}
		}
	}
	return 0;
}

/*
 * Calculate time in seconds from start_time plus +<upto>.
 */
static time_t
mk_time_exp_upto(time_t start_time, char upto)
{
	time_t		result_time = start_time;
	struct tm	tmp_tm;

	if (upto == UPTO_SIMPLE)
		return start_time;

	localtime_r(&result_time, &tmp_tm);

	if (upto == UPTO_MONTH) {
		/* up to the end of month */
		if (tmp_tm.tm_mon == 11) {
			tmp_tm.tm_mon = 0;
			++tmp_tm.tm_year;
		} else
			++tmp_tm.tm_mon;
		tmp_tm.tm_mday = 1;
		tmp_tm.tm_hour = tmp_tm.tm_min = tmp_tm.tm_sec = 0;
		return mktime(&tmp_tm);
	}
	/* up to the end of minute */
	result_time += MINUTE - tmp_tm.tm_sec;
	if (upto == UPTO_MINUTE)
		return result_time;
	++tmp_tm.tm_min;
	
	/* up to the end of hour */
	result_time += MINUTE * (60 - tmp_tm.tm_min);
	if (upto == UPTO_HOUR)
		return result_time;
	++tmp_tm.tm_hour;
	
	/* up to the end of day */
	result_time += HOUR * (24 - tmp_tm.tm_hour);
	if (upto == UPTO_DAY)
		return result_time;
	++tmp_tm.tm_wday;

	/* up to the end of week */
	if (tmp_tm.tm_wday != 1)
		result_time += DAY * (8 - tmp_tm.tm_wday);
	return result_time;	/* upto == UPTO_WEEK */
}

/*
 * Return calculated time for "+X" like time.
 */
static time_t
mk_time_exp(time_t start_time, const struct time_exp *texp)
{
	time_t		result_time;
	u_int		monthes, years;
	struct tm	result_tm;

	result_time = start_time;
	if (texp->side == 0)
		result_time = mk_time_exp_upto(start_time, texp->upto);
	result_time += texp->seconds;
	if (texp->monthes != 0) {
		localtime_r(&result_time, &result_tm);
		if (texp->monthes != 0) {
			if (result_tm.tm_mon + texp->monthes > 11) {
				monthes = texp->monthes - (11 - result_tm.tm_mon);
				years = monthes / 12;
				result_tm.tm_year += 1 + years;
				result_tm.tm_mon = monthes - 12 * years - 1;
			} else
				result_tm.tm_mon += texp->monthes;
			if (result_tm.tm_mday > 28) {
				switch (result_tm.tm_mon) {
				case 3:
				case 5:
				case 8:
				case 10:
					if (result_tm.tm_mday > 30)
						result_tm.tm_mday = 30;
					break;
				case 1:
					result_tm.tm_mday = result_tm.tm_year % 4 == 0 ? 29 : 28;
				}
			}
		}
		result_time = mktime(&result_tm);
	}
	return texp->side == 0 ? result_time : mk_time_exp_upto(result_time, texp->upto);
}

/*
 * Restart *limit, append 's' and 'z' timestamp if needed.
 */
static int
restart_limit(struct limit *limit)
{
	if (debug_limit > 0)
		syslog(LOG_INFO, "rule %s, limit %s: restart limit",
		    limit->rule->rulename, limit->limitname);
	if (Ftruncate_Seek(limit->fp, 0L, limit->filename) < 0)
		return -1;
	if (fprintf(limit->fp, "%020qu %020qu\n", 0ULL, limit->byte_limit) != LIMIT_LINE1_SIZE) {
		syslog(LOG_ERR, "fprintf(%s, \"%%020qu %%020qu\\n\"), failed: %m", limit->filename);
		return -1;
	}
	if (append_limit_ts(limit, LIMIT_STARTED, &curr_tm) < 0)
		return -1;
	limit->start_time = curr_time;
	limit->bcnt = 0;
	return append_limit_z_ts(limit);
}

/*
 * Just send message to syslog, that error in limit was fixed.
 */
static void
log_limit_fix(struct limit *limit)
{
	syslog(LOG_WARNING, "rule %s, limit %s: errors fixed, restart limit",
	    limit->rule->rulename, limit->limitname);
}

/*
 * Use curr_tm and curr_time to determine if timestamps for limit are correct.
 * Limits files were opened in init_db_rules() function.
 */
int
init_limits(int mode)
{
	char		*buf = NULL;
	size_t		bufsize;
	u_int		k;
	int		len;
	u_quad_t	old_size;
	struct rule 	*rule;
	struct limit	*limit;
	struct timestamp {
		short		ts_is_set;
		long		ts_offset;
		struct tm	ts_tm;
	}		ts_start, ts_zero, ts_reach, ts_expire, ts_exec1,
			ts_exec2, *ts_ptr;

	SLIST_FOREACH(rule, &rule_head, rule_entry) {
		SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
			if (fseek(limit->fp, 0L, SEEK_SET) < 0) {
				syslog(LOG_ERR, "init_limits: fseek(%s): %m", limit->filename);
				return -1;
			}

			if (mode == 0)
				if (lock_db_file_until_end(limit->filename, limit->fd, SEEK_SET) < 0)
					return -1;

			len = readline(&buf, &bufsize, limit->fp, limit->filename);
			if (len == 0 && feof(limit->fp) != 0) {
				/* file has been just created or it is empty */
				if (restart_limit(limit) < 0)
					return -1;
				continue;
			}
			if (len == 0) {
				/* XXX readline() can't return 0 without EOF */
				syslog(LOG_ERR, "read 0 bytes from file %s (first line)", limit->filename);
				return -1;
			}
			if (len < 0) {
				syslog(LOG_ERR, "cannot read first line from file %s", limit->filename);
				return -1;
			}
			if (REGEXEC(limit_line1, buf) != 0) {
				syslog(LOG_ERR, "%s: cannot recognize first line", limit->filename);
				return -1;
			}
			errno = 0;
			if (sscanf(buf, "%qu %qu", &limit->bcnt, &old_size) != 2) {
				syslog(LOG_ERR, "%s: sscanf(%s, \"%%qu %%qu\"): failed: %m", limit->filename, buf);
				return -1;
			}
			if (limit->byte_limit != old_size)
				syslog(LOG_WARNING, "rule %s, limit %s: parameter \"byte_limit\" was changed, old size = %s new size = %s",
				    rule->rulename, limit->limitname, show_bytes(old_size), show_bytes2(limit->byte_limit));

			ts_start.ts_is_set = ts_zero.ts_is_set = ts_reach.ts_is_set = 
			    ts_expire.ts_is_set = ts_exec1.ts_is_set = ts_exec2.ts_is_set = 0;
			for (k = 0; k < 7; ++k) {
				len = readline(&buf, &bufsize, limit->fp, limit->filename);
				if (len == 0 && feof(limit->fp) != 0) {
					if (k == 0) {
						syslog(LOG_ERR, "%s: too small file size", limit->filename);
						log_limit_fix(limit);
						if (restart_limit(limit) < 0)
							return -1;
						goto next_limit;
					}
					break;
				}
				if (len > 0 && k == 6) {
					syslog(LOG_ERR, "%s: too big file size (more than 6 timestamps)", limit->filename);
					return -1;
				}
				if (len == 0) {
					/* XXX readline() can't return 0 without EOF */
					syslog(LOG_ERR, "%s: read 0 bytes (%d line)", limit->filename, k + 2);
					return -1;
				}
				if (len < 0) {
					syslog(LOG_ERR, "%s: cannot read %d line from", limit->filename, k + 2);
					return -1;
				}
				if (REGEXEC(limit_timestamp, buf) != 0) {
					syslog(LOG_ERR, "%s: cannot recognize %d line", limit->filename, k + 2);
					return -1;
				}
				ts_ptr = NULL;
				switch (*buf) {
				case LIMIT_STARTED:
					if (k != 0)
						break;
					if (!ts_start.ts_is_set)
						ts_ptr = &ts_start;
					break;
				case LIMIT_ZEROED:
					if (k != 1)
						break;
					if (!ts_zero.ts_is_set)
						ts_ptr = &ts_zero;
					break;
				case LIMIT_REACHED:
					if ((ts_zero.ts_is_set && k != 2) ||
					    (!ts_zero.ts_is_set && k != 1))
						break;
					if (!ts_reach.ts_is_set)
						ts_ptr = &ts_reach;
					break;
				case LIMIT_EXECUTED:
					if (k == 2 || k == 3) {
						if (!ts_exec1.ts_is_set)
							ts_ptr = &ts_exec1;
					} else if (k == 4 || k == 5)
						if (!ts_exec2.ts_is_set)
							ts_ptr = &ts_exec2;
					break;
				case LIMIT_EXPIRED:
					if ((!ts_zero.ts_is_set && !ts_exec1.ts_is_set && k != 2) ||
					    (!ts_zero.ts_is_set && ts_exec1.ts_is_set && k != 3) ||
					    (ts_zero.ts_is_set && !ts_exec1.ts_is_set && k != 3) ||
					    (ts_zero.ts_is_set && ts_exec1.ts_is_set && k != 4))
						break;
					if (!ts_expire.ts_is_set)
						ts_ptr = &ts_expire;
					break;
				default:
					syslog(LOG_ERR, "init_limits: recognized but unknown type of limit timestamp: `%c'", *buf);
					return -1;
				}
				if (ts_ptr == NULL) {
					syslog(LOG_ERR, "%s: wrong order of timestamps", limit->filename);
					return -1;
				}
				ts_ptr->ts_is_set = 1;
				if ( (ts_ptr->ts_offset = ftell(limit->fp)) < 0) {
					syslog(LOG_ERR, "ftell(%s): %m", limit->filename);
					return -1;
				}
				memcpy(&ts_ptr->ts_tm, &curr_tm, sizeof curr_tm); /* init TZ parameters, etc. */
				errno = 0;
				if (sscanf(buf + 2, "%d.%d.%d/%d:%d:%d", &ts_ptr->ts_tm.tm_year,
				    &ts_ptr->ts_tm.tm_mon, &ts_ptr->ts_tm.tm_mday, &ts_ptr->ts_tm.tm_hour,
				    &ts_ptr->ts_tm.tm_min, &ts_ptr->ts_tm.tm_sec) != 6) {
					syslog(LOG_ERR, "%s: sscanf(\"%s\", \"%%d.%%d.%%d/%%d:%%d:%%d\"): failed: %m", limit->filename, buf + 2);
					return -1;
				}
				if (check_date(&ts_ptr->ts_tm, 0) < 0) {
					syslog(LOG_ERR, "%s: wrong values of date in %d line", limit->filename, k + 2);
					return -1;
				}
				ts_ptr->ts_tm.tm_year -= 1900;
				--ts_ptr->ts_tm.tm_mon;
			}

			if (!ts_start.ts_is_set) {
				syslog(LOG_ERR, "%s: first timestamp must be marked by `s'", limit->filename);
				return -1;
			}

			if (tmcmp(&ts_start.ts_tm, &curr_tm) > 0) {
				syslog(LOG_WARNING, "rule %s, limit %s: start_time = %d.%02d.%02d/%02d:%02d:%02d is greater than current time",
				    rule->rulename, limit->limitname,
				    ts_start.ts_tm.tm_year + 1900, ts_start.ts_tm.tm_mon + 1, ts_start.ts_tm.tm_mday,
				    ts_start.ts_tm.tm_hour, ts_start.ts_tm.tm_min, ts_start.ts_tm.tm_sec);
				log_limit_fix(limit);
				if (restart_limit(limit) < 0)
					return -1;
			} else
				limit->start_time = mktime(&ts_start.ts_tm);

			if (limit->bcnt < old_size) {
				/* limit isn't reached with old "size" */
				if (ts_reach.ts_is_set || ts_expire.ts_is_set ||
				    ts_exec1.ts_is_set || ts_exec2.ts_is_set) {
					syslog(LOG_ERR, "%s: limit is not reached with old size, wrong timestamps were found",
					    limit->filename);
					return -1;
				}
				if (mode == 1 && ts_zero.ts_is_set) {
					if (tmcmp(&curr_tm, &ts_zero.ts_tm) > 0) {
						if (debug_limit > 0) {
							syslog(LOG_INFO, "init_limits: rule %s, limit %s: old zero_time = %d.%02d.%02d/%02d:%02d:%02d is less than current time",
							    rule->rulename, limit->limitname,
							    ts_zero.ts_tm.tm_year + 1900, ts_zero.ts_tm.tm_mon + 1, ts_zero.ts_tm.tm_mday,
							    ts_zero.ts_tm.tm_hour, ts_zero.ts_tm.tm_min, ts_zero.ts_tm.tm_sec);
						}
						if (restart_limit(limit) < 0)
							return -1;
						continue;
					}
				}
				if (limit->byte_limit != old_size) {
					if (fseek(limit->fp, 0L, SEEK_SET) < 0) {
						syslog(LOG_ERR, "fseek(%s, 0, SEEK_SET): %m", limit->filename);
						return -1;
					}
					if (fprintf(limit->fp, "%020qu %020qu\n", limit->bcnt, limit->byte_limit) != LIMIT_LINE1_SIZE) {
						syslog(LOG_ERR, "init_limits: fprintf(%s, \"%%020qu %%020qu\\n\"), failed: %m", limit->filename);
						return -1;
					}
				}
				if (Ftruncate_Seek(limit->fp, ts_start.ts_offset, limit->filename) < 0)
					return -1;
				if (append_limit_z_ts(limit) < 0)
					return -1;
				if (mode == 1 && limit->zero_time_param.upto != UPTO_NOTSET) {
					if (curr_time > limit->zero_time) {
						struct tm	tmp_tm;

						localtime_r(&limit->zero_time, &tmp_tm);
						if (debug_limit > 0) {
							syslog(LOG_INFO, "init_limits: rule %s, limit %s: recalculated zero_time = %d.%02d.%02d/%02d:%02d:%02d is less than current time",
							    rule->rulename, limit->limitname,
							    tmp_tm.tm_year + 1900, tmp_tm.tm_mon + 1, tmp_tm.tm_mday,
							    tmp_tm.tm_hour, tmp_tm.tm_min, tmp_tm.tm_sec);
						}
						if (restart_limit(limit) < 0)
							return -1;
						continue;
					}
				}
			} else {
				/* limit is reached with old "size" */
				if (!ts_reach.ts_is_set) {
					syslog(LOG_ERR, "file %s: limit is reached with old size, cannot find reach_time line",
					    limit->filename);
					continue;
				}
				limit->reach_time = mktime(&ts_reach.ts_tm);
				if (mode == 1 && ts_expire.ts_is_set) {
					if (tmcmp(&curr_tm, &ts_expire.ts_tm) > 0) {
						if (debug_limit > 0) {
							syslog(LOG_INFO, "init_limits: rule %s, limit %s: old expire_time = %d.%02d.%02d/%02d:%02d:%02d less than current time",
							    rule->rulename, limit->limitname,
							    ts_expire.ts_tm.tm_year + 1900, ts_expire.ts_tm.tm_mon + 1, ts_expire.ts_tm.tm_mday,
							    ts_expire.ts_tm.tm_hour, ts_expire.ts_tm.tm_min, ts_expire.ts_tm.tm_sec);
						}
						if (restart_limit(limit) < 0)
							return -1;
						continue;
					}
				}
				if (ts_exec1.ts_is_set) {
					if (Ftruncate_Seek(limit->fp, ts_exec1.ts_offset, limit->filename) < 0)
						return -1;
				} else {
					if (Ftruncate_Seek(limit->fp, ts_reach.ts_offset, limit->filename) < 0)
						return -1;
				}
				if (append_limit_e_ts(limit) < 0)
					return -1;
				if (mode == 1 && limit->expire.time.upto != UPTO_NOTSET) {
					if (curr_time > limit->expire_time) {
						struct tm	tmp_tm;

						localtime_r(&limit->expire_time, &tmp_tm);
						if (debug_limit > 0) {
							syslog(LOG_INFO, "init_limits: rule %s, limit %s: recalculated expire_time = %d.%02d.%02d/%02d:%02d:%02d is less than current time",
							    rule->rulename, limit->limitname,
							    tmp_tm.tm_year + 1900, tmp_tm.tm_mon + 1, tmp_tm.tm_mday,
							    tmp_tm.tm_hour, tmp_tm.tm_min, tmp_tm.tm_sec);
						}
						if (restart_limit(limit) < 0)
							return -1;
						continue;
					}
				}
				limit->status = LIMIT_IS_REACHED | LIMIT_EXPIRE_CHECKED;
			}
next_limit:
			if (mode == 0)
				if (unlock_db_file(limit->filename, limit->fd) < 0)
					return -1;
		}
	}
	free(buf);
	return 0;
}

/*
 * ftruncate() file and seek() to the end of file *fp.
 */
static int
Ftruncate_Seek(FILE *fp, long length, const char *filename)
{
	if (fflush(fp) != 0) {
		syslog(LOG_ERR, "fflush(%s): %m", filename);
		return -1;
	}
	if (ftruncate(fileno(fp), length) < 0) {
		syslog(LOG_ERR, "ftruncate(%s, %ld): %m", filename, length);
		return -1;
	}
	if (fflush(fp) != 0) {
		syslog(LOG_ERR, "fflush(%s): %m", filename);
		return -1;
	}
	if (fseek(fp, length, SEEK_SET) < 0) {
		syslog(LOG_ERR, "fseek(%s, %ld, SEEK_SET): %m", filename, length);
		return -1;
	}
	return 0;
}

/*
 * Some of childs exited.
 */
static void
check_childs(void)
{
	int		status;
	pid_t		wpid;
	struct limit	*limit = NULL;

	while ( (wpid = waitpid(0, &status, WNOHANG)) > 0) {
		SLIST_FOREACH(limit, &wpid_head, wpid_entry)
			if (limit->wpid == wpid) {
				/*
				 * SLIST_REMOVE is slow, but we don't expect
				 * many elements in wpid_head (usually
				 * there is only one element there).
				 */
				SLIST_REMOVE(&wpid_head, limit, limit, wpid_entry);
				limit->status ^= LIMIT_EXEC;
				if (limit->rule->is_active)
					/* If rule is active, then this rule should be checked immediately. */
					limit->rule->wakeup = 0;
				if (debug_exec >= 3)
					syslog(LOG_INFO, "check_childs: rule %s, limit %s: PID %d exited",
					    limit->rule->rulename, limit->limitname, wpid);
				break;
			}
		/*
		 * We shall get here when we made reconfiguration
		 * and any child from previous configuration exited.
		 */
		if (limit == NULL) {
			syslog(LOG_INFO, "check_childs: waitpid returned PID %d, such PID is not expected", wpid);
			syslog(LOG_INFO, "check_childs: actually this is not a problem if you made reconfiguration");
		}
	}
	if (limit == NULL && wpid < 0 && errno != EINTR && errno != ECHILD)
		syslog(LOG_WARNING, "check_childs: waitpid: %m");
}

/*
 * Append 'z' timestamp to limit *limit.
 */
static int
append_limit_z_ts(struct limit *limit)
{
	if (limit->zero_time_param.upto != UPTO_NOTSET) {
		struct tm	tmp_tm;

		limit->zero_time = mk_time_exp(limit->start_time, &limit->zero_time_param);
		localtime_r(&limit->zero_time, &tmp_tm);
		if (append_limit_ts(limit, LIMIT_ZEROED, &tmp_tm) < 0)
			return -1;
	}
	return 0;
}

/*
 * Append 'e' timestamp to limit *limit.
 */
static int
append_limit_e_ts(struct limit *limit)
{
	if (limit->expire.time.upto != UPTO_NOTSET) {
		struct tm	tmp_tm;

		limit->expire_time = mk_time_exp(limit->reach_time, &limit->expire.time);
		localtime_r(&limit->expire_time, &tmp_tm);
		if (append_limit_ts(limit, LIMIT_EXPIRED, &tmp_tm) < 0)
			return -1;
	}
	return 0;
}
