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
 *
 *   @(#)$Id: rules.h,v 1.6.2.7 2003/07/08 08:30:01 simon Exp $
 */

#ifndef IPA_RULES_H
#define IPA_RULES_H

#include <sys/queue.h>

#include "cmd.h"
#include "kipfil.h"
#ifdef __FreeBSD__
# include "kipfw.h"
# include "kip6fw.h"
#endif
#include "kpf.h"

#define ADD	  1
#define SUB	(-1)


#if defined(WITH_IPFW) || defined(WITH_IP6FW)
/*
 * One element in "ipfw" or "ip6fw" parameter.
 */

/*
 * In original structure ip_fw there is only one field for rule number.
 * I add extra field subnumber: if there are some rules with the same number
 * I distinguish such rules by subnumbers, first rule in the set of such
 * rules has subnumber equal to 0. 
 */
struct ipfwac {
	u_short		number;		/* IPFW rule number */
	u_int		subnumber;	/* IPFW rule subnumber */
	short		seen;		/* 1, if bcnt_old is known. */
	short		action;		/* subtract or add */
	u_quad_t	bcnt_old;	/* old value of fw_bcnt (struct ip_fw) */
};
#endif /* WITH_IPFW || WITH_IP6FW */

#ifdef WITH_PF
/*
 * One element in "pf" parameter.
 */
struct pfac {
	u_int		number;		/* PF rule number. */
	short		seen;		/* 1, if bcnt_old is known. */
	short		action;		/* Subtract or add. */
	u_quad_t	bcnt_old;	/* Old value of counter. */
};
#endif /* WITH_PF */

#ifdef WITH_IPFIL
struct ipfilac_rule {
	u_int		rule_number;	/* Number of the rule in the group. */
	short		seen;		/* 1, if bcnt_old is known. */
	short		action;		/* Subtract or add. */
	u_quad_t	bcnt_old;	/* Old value of fr_bytes (struct frentry). */
};

struct ipfilac_group {
	u_int		group_number;	/* The group number. */
	struct ipfilac_rule	*rule;	/* Array of rules in this group. */
	u_int		nrule;		/* Number of rules. */
};

struct ipfilac {
	struct ipfilac_group	*group;	/* Groups of one type. */
	u_int		ngroup;		/* Number of groups. */
};
#endif /* WITH_IPFIL */

#define UPTO_NOTSET	'-'
#define UPTO_SIMPLE	' '
#define UPTO_MINUTE	'm'
#define UPTO_HOUR	'h'
#define UPTO_dAY	'd'
#define UPTO_DAY	'D'
#define UPTO_wEEK	'w'
#define UPTO_WEEK	'W'
#define UPTO_MONTH	'M'

/*
 * [+<X>] <time> or <time> +<X> like parameter value.
 */
struct time_exp {
	time_t		seconds;	/* number of seconds */
	u_int		monthes;	/* number of monthes */
	char		upto;		/* m, h, D, W, M, - (not set) */
	short		side;		/* 0 if +X <time>, 1 if <time> +X */
};

/*
 * Describes "db_group" parameter.
 */
struct db_group {
	int	group_set;		/* 1, if "db_group" parameter is used */
	u_long	group_id;		/* GID */
	int	group_named;		/* 1, if group was given by name */
	mode_t	dir_mode;		/* mode of the database directory */
	mode_t	file_mode;		/* mode of the database file */
};

/*
 * One time interval in the worktime for one week day.
 */
struct interval {
	u_short		h1, m1, h2, m2;	/* h1:m1 - h2:m2 */
	int		sec1, sec2;	/* the same interval in seconds */
};

/*
 * Worktime for one week day.
 */
struct worktime {
	struct interval	*interval;	/* ptr. to interval list */
	u_int		ninterval;	/* size of prev. array */
};

/*
 * limit { expire {}} section.
 */
struct expire {
	struct time_exp	time;		/* "expire_time" parameter */
	struct cmd	*cmd;		/* "exec" parameters */
	u_int		ncmd;		/* size of prev. array */
};

/*
 * limit { reach {}} section.
 */
struct reach {
	struct cmd	*cmd;		/* "exec" parameters */
	u_int		ncmd;		/* size of prev. array */
};

/*
 * rule { limit {}} section.
 */
struct limit {
	SLIST_ENTRY(limit)	limit_entry;
	SLIST_ENTRY(limit)	wpid_entry;

	FILE		*fp;		/* ptr. on FILE stream for limit db */
	int		fd;		/* == fileno(fp) */
	char		*filename;	/* name of limit database file */
	char		*limitname;	/* name of limit */
	u_quad_t	byte_limit;	/* limit { byte_limit } */
	u_quad_t	bcnt;		/* byte counter for this limit */
	u_quad_t	bcnt_sub;	/* number of bytes, which should be subtracted
					   from limit counter. */
	struct reach	reach;		/* limit { reach {}} */
	struct time_exp	zero_time_param;/* limit { zero_time } */
	struct expire	expire;		/* limit { expire {}} */
	struct commands	rc[2];		/* rc[0] -- limit { startup {}},
					   rc[1] -- limit { shutdown {}} */
	char		*info;		/* limit { info } */
	pid_t		wpid;		/* PID of background process which
					   runs "exec" parameter commands */
	u_short		is_changed;	/* 1, if bcnt was modified */
	u_short		status;		/* status LIMIT_* */
	struct worktime	worktime[7];	/* limit { worktime } */
	int		use_worktime;	/* 1, if "worktime" parameter is used */
	u_int		worktime_curr_interval;
					/* current worktime's *interval */
	int		worktime_curr_interval_flag;
					/* 1, if we already in current
					   worktime's interval */
	int		is_active;	/* 1, if worktime of limit allows to
					   work with this limit */
	time_t		wakeup_worktime;/* time when to wake up and check worktime parameter */
	time_t		start_time;	/* time when limit was started */
	time_t		zero_time;	/* time when limit should be zeroed */
	time_t		reach_time;	/* time when limit was reached */
	time_t		expire_time;	/* time when limit will be expired */
	struct rule	*rule;
};

#define	LIMIT_IS_REACHED	0x0001
#define LIMIT_EXEC		0x0002
#define LIMIT_EXPIRE_CHECKED	0x0004
#define LIMIT_EXPIRE_EXEC	0x0008

/*
 * rule {} section.
 */
struct rule {
	SLIST_ENTRY(rule) rule_entry;

	char		*rulename;	/* name of rule */
	u_quad_t	bcnt;		/* byte counter for this rule */
	u_quad_t	bcnt_sub;	/* nuber of bytes, which should be subtracted
					   from bcnt, when it is greater than zero */
	u_int		update_db_time;	/* interval in sec. when to update counters,
					   rule { update_db_time } */
	u_int		append_db_time;	/* interval in sec. when to append new record in data base.
					   rule { append_db_time } */
	time_t		wakeup;		/* time in sec. when to wake up */
	time_t		wakeup_worktime;/* time when to wake up and check worktime parameter */
	time_t		newrec_time;	/* time when to append new record in data base */
	FILE		*fp;		/* ptr. on FILE stream for db file */
	int		fd;		/* == fileno(fp) */
	char		*filename;	/* name of rule database file */
	u_quad_t	maxchunk;	/* rule { maxchunk } */
#ifdef WITH_IPFW
	struct ipfwac	*ipfwac;	/* ptr. on array for IPFW accounting */
	u_int		nipfwac;	/* size of prev. array */
#endif
#ifdef WITH_IP6FW
	struct ipfwac	*ip6fwac;	/* ptr. on array for IP6FW accounting */
	u_int		nip6fwac;	/* size of prev. array */
#endif
#ifdef WITH_PF
	struct pfac	*pfac;		/* ptr. on array for PF accounting */
	u_int		npfac;		/* size of prev. array */
#endif
#ifdef WITH_IPFIL
	struct ipfilac	ipfilac_in;	/* "in" IPFIL accounting rules. */
	struct ipfilac	ipfilac_out;	/* "out" IPFIL accounting rules. */
#endif
	SLIST_HEAD(, limit) limit_head;	/* limit {} sections */
	struct commands	rc[2];		/* rc[0] -- rule { startup {}},
					   rc[1] -- rule { shutdown {}} */
	struct db_group	db_group;	/* rule { db_group } */
	char		*info;		/* rule { info } */
	struct worktime	worktime[7];	/* rule { worktime } */
	int		use_worktime;	/* 1, if "worktime" parameter is used
					   in the "rule" or any "limit" section */
	int		use_rule_worktime; /* 1, if "worktime" parameter is
					      used in the "rule" section */
	u_int		worktime_curr_interval;
					/* current worktime's *interval */
	int		worktime_curr_interval_flag;
					/* 1, if we already in current
					   worktime's interval */
	int		firstcall;	/* 0, if rules.c:do_ipac() function
					   wased passed one time, also it is used
					   if "worktime" parameter is used */
	int		is_active;	/* 1, if worktime allows to
					   work with this rule */
};

SLIST_HEAD(rule_slisthead, rule);

extern struct rule_slisthead rule_head;
extern int		use_worktime;
extern struct worktime	worktime_global[7];
extern struct commands	startup_global, shutdown_global;

extern int		run_ipac(void);
extern void		end_work(int), sig_alrm(int), reconfigure(int),
			sig_chld(int), force_db_dump(int);
extern int		run_rules_rc(int);
extern int		init_limits(int);

#endif /* !IPA_RULES_H */
