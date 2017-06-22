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
  "@(#)$Id: config.c,v 1.6.2.10 2003/07/08 08:30:01 simon Exp $";
#endif /* !lint */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <regex.h>
#include <stdarg.h>

#include "config.h"

#include "common.h"
#include "db.h"
#include "debug.h"
#include "ipa.h"
#include "path.h"
#include "rules.h"
#include "mysql.h"

static struct rule	*currule;	/* current rule */
static struct limit	*curlimit;	/* current limit */
static u_int	ruleno;			/* order number of current rule */

typedef enum {
	NONE_SECTION,
	RULE_SECTION,
	GLOBAL_SECTION,
	LIMIT_SECTION,
	EXPIRE_SECTION,
	STARTUP_SECTION,
	IF_LIMIT_SECTION,
	IF_NOLIMIT_SECTION,
	SHUTDOWN_SECTION,
	DEBUG_SECTION,
	REACH_SECTION,
	INCLUDE_SECTION
} SECTION;

char		*cfgfilename_main = CFGFILE;	/* main (default) configuration file name */
static char	*cfgfilename;			/* current configuration file name */

static int	only_abs_paths;			/* global { only_abs_paths } */
static u_int	update_db_time_global;		/* global { update_db_time } */
static u_int	append_db_time_global;		/* global { append_db_time } */
static u_quad_t	maxchunk_global;		/* global { maxchunk } */
static struct db_group db_group_global;		/* global { db_group } */
static int	use_syslog = 1;			/* ==0 if -d switch was used */

static PARSING_MODE	parsing_mode;

static u_int	lineno;		/* number of line in the configuration file */
static SECTION	section, section_prev, section_top;
static int	worktime_global_set;
static int	global_section_set, debug_section_set, include_section_set;
static int	only_abs_paths_set, lock_db_set;
#ifdef WITH_MYSQL
static int     sql_name_set, sql_user_set, sql_pswd_set,
               sql_host_set, sql_port_set;
#endif /* WITH_MYSQL */
static int	debug_limit_set = 0, debug_exec_set = 0,
		debug_time_set = 0, debug_worktime_set = 0,
		debug_lock_set = 0, debug_include_set = 0;

static regex_t	reg_rule, reg_emptyline, reg_time_val, reg_size_val,
		reg_limit, reg_exec, reg_if_limit,
		reg_if_nolimit,	reg_time_exp_val, reg_db_group_val,
		reg_worktime_val, reg_yesno_val, reg_file,
		reg_files;

#ifdef WITH_MYSQL
static regex_t reg_sql_port;
#endif /* WITH_MYSQL */

#ifdef WITH_IPFW
static int	debug_ipfw_set = 0;
#endif
#ifdef WITH_IP6FW
static int	debug_ip6fw_set = 0;
#endif
#if defined(WITH_IPFW) || defined(WITH_IP6FW)
static regex_t	reg_ipfw_val;
#endif

#ifdef WITH_IPFIL
static int	debug_ipfil_set = 0;
static regex_t	reg_ipfil_val;
#endif

#ifdef WITH_PF
static int	debug_pf_set = 0;
static regex_t	reg_pf_val;
#endif

static int	build_config_regexes(void);
#ifdef __GNUC__
static void	Syslog(int, const char *, ...) __attribute__ ((format (printf, 2, 3)));
static void	line_err(const char *, const char *, ...) __attribute__ ((format (printf, 2, 3)));
#endif /* __GNUC__ */

static char	*show_bytes_buf = NULL;


/*
 * include {
 *     file = filename
 *     file(?) = filename
 *     files(directory) = regular-expression
 *     files(?)(directory) = regular-expression
 * }
 */
static struct include {
	char	*file;			/* file name for "file" or RE if "files" */
	char	*dir;			/* directory name for "files"	*/
	int	question;		/* ==1 if "?" is used		*/
	int	use_re;			/* ==1 if "files" is used	*/
	regex_t	re;			/* compiled RE if use_re == 1	*/
} *include;

static u_int	ninclude,		/* size of include array */
		nincluded;		/* number of really included files */

#define KBYTE	(1024ULL)
#define MBYTE	(1024ULL * KBYTE)
#define GBYTE	(1024ULL * MBYTE)
#define TBYTE	(1024ULL * GBYTE)

/*
 * Strip white-space characters from the beginning of a string.
 */
static char *
skip_spaces(char *s)
{
	for (; *s != '\0'; ++s)
		if (*s != ' ' && *s != '\t')
			break;
	return s;
}

/*
 * Strip non white-space characters from the beginning of a string.
 */
static char *
skip_chars(char *s)
{
	for (; *s != '\0'; ++s)
		if (*s == ' ' || *s == '\t')
			break;
	return s;
}

/*
 * Remove trailing white-space characters.
 */
static void
remove_trailing_spaces(char *s)
{
	char	*ptr;

	ptr = s + strlen(s) - 1;
	do {
		if (*ptr != ' ' && *ptr != '\t') {
			*(ptr + 1) = '\0';
			break;
		}
	} while (ptr-- != s);
}

/*
 * Wrapper for syslog() function.
 * If use_syslog == 1 then syslog() is used,
 *                    else stdout stream is used.
 * "%m" is expected at the end of string.
 */
static void
Syslog(int priority, const char *message, ...)
{
	int	errno_save = errno;
	va_list	ap;

	va_start(ap, message);
	if (use_syslog)
		vsyslog(priority, message, ap);
	else {
		char	*prio;

		switch (priority) {
		case LOG_INFO:
			prio = "INFO";
			break;
		case LOG_WARNING:
			prio = "WARNING";
			break;
		case LOG_ERR:
			prio = "ERR";
			break;
		default:
			prio = "???";
		}
		printf("syslog(LOG_%s): ", prio);
		vprintf(message, ap);
		if (strstr(message, "%m") == NULL)
			printf("\n");
		else
			printf("\b%s\n", strerror(errno_save));
		fflush(stdout);
	}
	va_end(ap);
}

/*
 * Output error message for some line in configuration file.
 */
static void
line_err(const char *line, const char *message, ...)
{
	int	errno_save = errno;
	va_list	ap;

	va_start(ap, message);
	if (line != NULL)
		Syslog(LOG_ERR, "file %s, line %u \"%s\"", cfgfilename, lineno, line);
	else
		Syslog(LOG_ERR, "file %s, line %u", cfgfilename, lineno);
	if (message != NULL) {
		if (use_syslog)
			vsyslog(LOG_ERR, message, ap);
		else {
			printf("syslog(LOG_ERR): ");
			vprintf(message, ap);
			if (strstr(message, "%m") == NULL)
				printf("\n");
			else
				printf("\b%s\n", strerror(errno_save));
		}
		fflush(stdout);
	}
	va_end(ap);
}

/*
 * Output error message about unknown format of some parameter.
 */
static void
wrong_format_msg(const char *line, const char *token, const char *message)
{
	char	*ch = *message == '\0' ? "" : ": ";

	switch (section) {
	case RULE_SECTION:
		line_err(line, "rule %s: wrong format for \"%s\"%s%s",
		    currule->rulename, token, ch, message);
		break;
	case LIMIT_SECTION:
		line_err(line, "rule %s, limit %s: wrong format for \"%s\"%s%s",
		    currule->rulename, curlimit->limitname, token, ch, message);
		break;
	case GLOBAL_SECTION:
		line_err(line, "global section: wrong format for \"%s\"%s%s",
		    token, ch, message);
		break;
	default:
		line_err(line, "wrong format for \"%s\"%s%s", token, ch, message);
	}
}

/*
 * Convert string to unsigned integer.
 * Wrapper for strtoul() function.
 *
 * XXX Asumed that sizeof(u_long) >= sizeof(u_int).
 */
static int
Strtoui(u_int *result, const char *nptr, char **endptr)
{
	u_long		val;
	int		errno_save = errno;

	errno = 0;
	val = strtoul(nptr, endptr, 10);
	if (val > UINT_MAX)
		errno = ERANGE;
	if (errno != 0) {
		line_err(nptr, "strtoul: %s", strerror(errno));
		return -1;
	}
	errno = errno_save;
	*result = val;
	return 0;
}

/*
 * Convert string to unsigned long long integer (unsigned quad).
 * Wrapper for strtouq() function.
 */
static int
Strtouq(u_quad_t *result, const char *nptr, char **endptr)
{
	u_quad_t	val;
	int		errno_save = errno;

	errno = 0;
	val = strtouq(nptr, endptr, 10);
	if (errno != 0) {
		line_err(nptr, "strtouq: %s", strerror(errno));
		return -1;
	}
	errno = errno_save;
	*result = val;
	return 0;
}

/*
 * Convert full string to unsigned long integer.
 */
static int
fullstrtoul(u_long *result, const char *nptr)
{
	char	*endptr;
	u_long	val;
	int	errno_save = errno;
	
	errno = 0;
	val = strtoul(nptr, &endptr, 10);
	if (errno != 0) {
		line_err(nptr, "strtoul: %s", strerror(errno));
		return -1;
	}
	errno = errno_save;
	if (*endptr != '\0')
		return -2;
	*result = val;
	return 0;
}

/*
 * Parse "rule" section: get rule name.
 */
static int
parse_rule(char *s)
{
	int		i;
	struct rule	*lastrule = currule;

	s = skip_spaces(skip_chars(s)); /* skip "rule[ \t]+" */
	SLIST_FOREACH(currule, &rule_head, rule_entry)
		if (strcmp(s, currule->rulename) == 0) {
			line_err(s, "duplicated \"rule %s\" section", s);
			return -1;
		}
	if ( (currule = calloc(1, sizeof *currule)) == NULL) {
		Syslog(LOG_ERR, "calloc: %m");
		return -1;
	}
	if (SLIST_EMPTY(&rule_head))
		SLIST_INSERT_HEAD(&rule_head, currule, rule_entry);
	else
		SLIST_INSERT_AFTER(lastrule, currule, rule_entry);
	SLIST_INIT(&currule->limit_head);
	currule->fp = NULL;
	currule->firstcall = 1;
#ifdef WITH_IPFW
	currule->ipfwac = NULL;
#endif
#ifdef WITH_IP6FW
	currule->ip6fwac = NULL;
#endif
#ifdef WITH_IPFIL
	currule->ipfilac_in.group = currule->ipfilac_out.group = NULL;
	currule->ipfilac_in.ngroup = currule->ipfilac_out.ngroup = 0;
#endif
#ifdef WITH_PF
	currule->pfac = NULL;
#endif
	currule->rc[0].cmd = currule->rc[0].cmd_if_limit = currule->rc[0].cmd_if_nolimit = NULL;
	currule->rc[0].ncmd = currule->rc[0].ncmd_if_limit = currule->rc[0].ncmd_if_nolimit = 0;
	currule->rc[1].cmd = currule->rc[1].cmd_if_limit = currule->rc[1].cmd_if_nolimit = NULL;
	currule->rc[1].ncmd = currule->rc[1].ncmd_if_limit = currule->rc[1].ncmd_if_nolimit = 0;
	currule->info = NULL;
	currule->is_active = 1;
	for (i = 0; i < 7; ++i) {
		currule->worktime[i].interval = NULL;
		currule->worktime[i].ninterval = 0;
	}
	/*
	 * By default owner of any file in the rule directory in the database
	 * is owned by 0:0 and it is not allowed to access for the group
	 * or other users.
	 */
	currule->db_group.group_set = 0;
	currule->db_group.group_id = 0;
	currule->db_group.dir_mode = DB_DIR_PERM_U;
	currule->db_group.file_mode = DB_FILE_PERM_U;
	if ( (currule->rulename = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	++ruleno;
	return 0;
}

#ifdef WITH_IPFW
/*
 * Parse "ipfw" parameter.
 */
static int
parse_ipfw(char *s)
{
	u_int		number, subnumber, i, found_number;
	short		action;
	char		*endptr;
	struct ipfwac	*ipfwacp;

	for (;;) {
		s = skip_spaces(s);
		if (*s == '\0') {
			use_ipfw = 1;
			return 0;	/* EOL */
		}
		if (*s == '-') {
			action = SUB;
			++s;
		} else
			action = ADD;
		if (Strtoui(&number, s, &endptr) < 0)
			return -1;
		if (number > IPFW_NUMBER_MAX) {
			line_err(s, "rule %s: IPFW rule number should be less than or equal to %d",
			    currule->rulename, IPFW_NUMBER_MAX);
			return -1;
		}
		s = endptr;
		subnumber = 0;
		if (*s == '.') {
			if (Strtoui(&subnumber, ++s, &endptr) < 0) {
				line_err((char *)NULL, "rule %s: IPFW rule subnumber should be less than %u",
				    currule->rulename, UINT_MAX);
				return -1;
			}
			if (number == IPFW_NUMBER_MAX && subnumber != 0) {
				line_err((char *)NULL, "rule %s: subnumbers for IPFW rule %d are not allowed",
				    currule->rulename, IPFW_NUMBER_MAX);
				return -1;
			}
			s = endptr;
		}
		for (i = found_number = 0, ipfwacp = currule->ipfwac; i < currule->nipfwac; ++ipfwacp, ++i)
			if (ipfwacp->number == number && ipfwacp->subnumber == subnumber) {
				found_number = 1;
				break;
			}
		if (found_number) {
			if (currule->ipfwac[i].action != action) {
				line_err((char *)NULL, "rule %s: IPFW rules %u.%u and -%u.%u have no effect",
				    currule->rulename, number, subnumber, number, subnumber);
				return -1;
			}
			line_err((char *)NULL, "rule %s: duplicated IPFW rule %u.%u",
			     currule->rulename, number, subnumber);
			return -1;
		}
		if ( (ipfwacp = realloc(currule->ipfwac, (currule->nipfwac + 1) * sizeof *ipfwacp)) == NULL) {
			Syslog(LOG_ERR, "realloc: %m");
			return -1;
		}
		currule->ipfwac = ipfwacp;
		ipfwacp += currule->nipfwac;
		++currule->nipfwac;
		ipfwacp->number = (u_short)number;
		ipfwacp->subnumber = subnumber;
		ipfwacp->seen = 0;
		ipfwacp->action = action;
	}
	/* NOTREACHED */
}
#endif /* WITH_IPFW */

#ifdef WITH_IP6FW
/*
 * Parse "ip6fw" parameter.
 */
static int
parse_ip6fw(char *s)
{
	u_int		number, subnumber, i, found_number;
	short		action;
	char		*endptr;
	struct ipfwac	*ip6fwacp;

	for (;;) {
		s = skip_spaces(s);
		if (*s == '\0') {
			use_ip6fw = 1;
			return 0;	/* EOL */
		}
		if (*s == '-') {
			action = SUB;
			++s;
		} else
			action = ADD;
		if (Strtoui(&number, s, &endptr) < 0)
			return -1;
		if (number > IP6FW_NUMBER_MAX) {
			line_err(s, "rule %s: IP6FW number should be less than or equal to %d",
			    currule->rulename, IP6FW_NUMBER_MAX);
			return -1;
		}
		s = endptr;
		subnumber = 0;
		if (*s == '.') {
			if (Strtoui(&subnumber, ++s, &endptr) < 0) {
				line_err((char *)NULL, "rule %s: IP6FW subnumber should be less than %u",
				    currule->rulename, UINT_MAX);
				return -1;
			}
			if (number == IP6FW_NUMBER_MAX && subnumber != 0) {
				line_err((char *)NULL, "rule %s: subnumbers for IP6FW rule %d is not allowed",
				    currule->rulename, IP6FW_NUMBER_MAX);
				return -1;
			}
			s = endptr;
		}
		for (i = found_number = 0, ip6fwacp = currule->ip6fwac; i < currule->nip6fwac; ++ip6fwacp, ++i)
			if (ip6fwacp->number == number && ip6fwacp->subnumber == subnumber) {
				found_number = 1;
				break;
			}
		if (found_number) {
			if (currule->ip6fwac[i].action != action) {
				line_err((char *)NULL, "rule %s: IP6FW rules %u.%u and -%u.%u have no effect",
				    currule->rulename, number, subnumber, number, subnumber);
				return -1;
			}
			line_err((char *)NULL, "rule %s: duplicated IP6FW rule %u.%u",
			     currule->rulename, number, subnumber);
			return -1;
		}
		if ( (ip6fwacp = realloc(currule->ip6fwac, (currule->nip6fwac + 1) * sizeof *ip6fwacp)) == NULL) {
			Syslog(LOG_ERR, "realloc: %m");
			return -1;
		}
		currule->ip6fwac = ip6fwacp;
		ip6fwacp += currule->nip6fwac;
		++currule->nip6fwac;
		ip6fwacp->number = (u_short)number;
		ip6fwacp->subnumber = subnumber;
		ip6fwacp->seen = 0;
		ip6fwacp->action = action;
	}
	/* NOTREACHED */
}
#endif /* WITH_IP6FW */

#ifdef WITH_IPFIL
/*
 * Parse "ipfil" parameter.
 */
static int
parse_ipfil(char *s)
{
	char		type, *endptr;
	short		action;
	int		found_group_flag;
	u_int		i, j;
	u_int		rule_number, group_number;
	struct ipfilac		*ipfilacp;
	struct ipfilac_group	*groupp;
	struct ipfilac_rule	*rulep;

	for (;;) {
		s = skip_spaces(s);
		if (*s == '\0') {
			use_ipfil = 1;
			return 0;	/* EOL */
		}
		if (*s == '-') {
			action = SUB;
			++s;
		} else
			action = ADD;
		type = *s;
		++s;
		if (*s == '@') {
			group_number = 0;
			++s;
		} else {
			if (Strtoui(&group_number, s, &endptr) < 0)
				return -1;
			if (group_number > IPFIL_GROUP_NUMBER_MAX) {
				line_err((char *)NULL, "rule %s: IPFIL group should be less than %u",
				    currule->rulename, IPFIL_GROUP_NUMBER_MAX);
				return -1;
			}
			s = endptr + 1;
		}
		if (Strtoui(&rule_number, s, &endptr) < 0)
			return -1;
		if (rule_number > IPFIL_RULE_NUMBER_MAX) {
			line_err((char *)NULL, "rule %s: IPFIL rule number should be less than %u",
			    currule->rulename, IPFIL_RULE_NUMBER_MAX);
			return -1;
		}
		if (rule_number == 0) {
			line_err((char *)NULL, "rule %s: IPFIL rule number should be greater than zero", currule->rulename);
			return -1;
		}
		s = endptr;
		if (type == 'i') {
			ipfilacp = &currule->ipfilac_in;
			use_ipfil_in = 1;
		} else {
			ipfilacp =  &currule->ipfilac_out;
			use_ipfil_out = 1;
		}
		found_group_flag = 0;
		for (i = 0, groupp = ipfilacp->group; i < ipfilacp->ngroup; ++groupp, ++i)
			if (groupp->group_number == group_number) {
				found_group_flag = 1;
				for (j = 0, rulep = groupp->rule; j < groupp->nrule; ++rulep, ++j)
					if (rulep->rule_number == rule_number) {
						if (rulep->action != action) {
							line_err((char *)NULL, "rule %s: IPFIL rules %c%u@%u and -%c%u@%u have no effect",
							    currule->rulename, type, group_number, rule_number, type, group_number, rule_number);
							return -1;
						}
						line_err((char *)NULL, "rule %s: duplicated IPFIL rule %c%u@%u",
						    currule->rulename, type, group_number, rule_number);
						return -1;
					}
				break;
			}
		if (found_group_flag) {
			/* Group is present. */
			if ( (rulep = realloc(groupp->rule, (groupp->nrule + 1) * sizeof *rulep)) == NULL) {
				Syslog(LOG_ERR, "realloc: %m");
				return -1;
			}
			groupp->rule = rulep;
			rulep += groupp->nrule;
			++groupp->nrule;
		} else {
			/* Create group. */
			if ( (groupp = realloc(ipfilacp->group, (ipfilacp->ngroup + 1) * sizeof *groupp)) == NULL) {
				Syslog(LOG_ERR, "realloc: %m");
				return -1;
			}
			ipfilacp->group = groupp;
			groupp += ipfilacp->ngroup;
			++ipfilacp->ngroup;
			if ( (rulep = malloc(sizeof *rulep)) == NULL) {
				Syslog(LOG_ERR, "malloc: %m");
				return -1;
			}
			groupp->group_number = group_number;
			groupp->rule = rulep;
			groupp->nrule = 1;
		}
		rulep->rule_number = rule_number;
		rulep->seen = 0;
		rulep->action = action;
	}
	/* NOTREACHED */
}
#endif /* WITH_IPFIL */

#ifdef WITH_PF
/*
 * Parse "pf" parameter.
 */
static int
parse_pf(char *s)
{
	u_int		number, i, found_number;
	short		action;
	char		*endptr;
	struct pfac	*pfacp;

	for (;;) {
		s = skip_spaces(s);
		if (*s == '\0') {
			use_pf = 1;
			return 0;	/* EOL */
		}
		if (*s == '-') {
			action = SUB;
			++s;
		} else
			action = ADD;
		if (Strtoui(&number, s, &endptr) < 0)
			return -1;
		if (number > PF_NUMBER_MAX) {
			line_err((char *)NULL, "rule %s: PF rule number should be less than %u",
			    currule->rulename, UINT_MAX);
			return -1;
		}
		s = endptr;
		for (i = found_number = 0, pfacp = currule->pfac; i < currule->npfac; ++pfacp, ++i)
			if (pfacp->number == number) {
				found_number = 1;
				break;
			}
		if (found_number) {
			if (pfacp->action != action) {
				line_err((char *)NULL, "rule %s: PF rules %u and -%u have no effect",
				    currule->rulename, number, number);
				return -1;
			}
			line_err((char *)NULL, "rule %s: duplicated PF rule %u",
			    currule->rulename, number);
			return -1;
		}
		if ( (pfacp = realloc(currule->pfac, (currule->npfac + 1) * sizeof * pfacp)) == NULL) {
			Syslog(LOG_ERR, "realloc: %m");
			return -1;
		}
		currule->pfac = pfacp;
		pfacp += currule->npfac;
		++currule->npfac;
		pfacp->number = number;
		pfacp->action = action;
		pfacp->seen = 0;
	}
	/* NOTREACHED */
}
#endif /* WITH_PF */

/*
 * Parse "time" value.
 */
static int
parse_time(char *s, u_int *r)
{
	int	level = 0, err = 0;
	u_int	value, result = 0;
	char	*endptr;

	for (;;) {
		s = skip_spaces(s);
		if (*s == '\0') {
			*r = result;
			return 0;	/* EOL */
		}
		if (Strtoui(&value, s, &endptr) < 0)
			return -1;
		s = endptr;
		switch (*s) {
		case 'h':
			if (level > 0)
				err = 1;
			else {
				level = 1;
				value *= HOUR;
			}
			break;
		case 'm':
			if (level > 1)
				err = 1;
			else {
				level = 2;
				value *= MINUTE;
			}
			break;
		default: /* 's' */
			if (level > 2)
				err = 1;
			else
				level = 3;
		}
		if (err) {
			line_err(s, "wrong time format");
			return -1;
		}
		if (result > UINT_MAX - value) {
			line_err(s, "too big value for time format");
			return -1;
		}
		result += value;
		++s;
	}
	/* NOTREACHED */
}

/*
 * Parse "update_db_time" parameter.
 */
static int
parse_update_db_time(char *s)
{
	u_int	result;

	if (parse_time(s, &result) < 0)
		return -1;
	if (result == 0) {
		line_err(s, "parameter \"update_db_time\" should be greater than zero");
		return -1;
	}
	if (section == RULE_SECTION)
		currule->update_db_time = result;
	else /* section == GLOBAL_SECTION */
		update_db_time_global = result;
	return 0;
}

/*
 * Parse "append_db_time" parameter.
 */
static int
parse_append_db_time(char *s)
{
	u_int	result;

	if (parse_time(s, &result) < 0)
		return -1;
	if (result == 0) {
		line_err(s, "parameter \"append_db_time\" should be greater than zero");
		return -1;
	}
	if (section == RULE_SECTION)
		currule->append_db_time = result;
	else /* section == GLOBAL_SECTION */
		append_db_time_global = result;
	return 0;
}

/*
 * Parse "size" value.
 *
 * XXX more tests should be done for (value * xBYTE).
 */
static int
parse_size(char *s)
{
	char		*p = s, *endptr;
	int		level = 0, err = 0;
	u_quad_t	value, result = 0;

	for (;;) {
		p = skip_spaces(p);
		if (*p == '\0')
			break;		/* EOL */
		if (Strtouq(&value, p, &endptr) < 0)
			return -1;
		p = endptr;
		switch (*p) {
		case 't':
		case 'T':
			if (level > 0)
				err = 1;
			else {
				level = 1;
				value *= TBYTE;
			}
			break;
		case 'g':
		case 'G':
			if (level > 1)
				err= 1;
			else {
				level = 2;
				value *= GBYTE;
			}
			break;
		case 'm':
		case 'M':
			if (level > 2)
				err= 1;
			else {
				level = 3;
				value *= MBYTE;
			}
			break;
		case 'k':
		case 'K':
			if (level > 3)
				err= 1;
			else {
				level = 4;
				value *= KBYTE;
			}
			break;
		default: /* 'b' or 'B' */
			if (level > 4)
				err= 1;
			else
				level = 5;
		}
		if (err) {
			line_err(p, "wrong size format");
			return -1;
		}
		if (result > UQUAD_MAX - value) {
			line_err(p, "too big value for size format");
			return -1;
		}
		result += value;
		++p;
	}
	if (result == 0) {
		line_err(s, "parameter \"%s\" should be greater than zero",
		    section == LIMIT_SECTION ? "byte_limit" : "maxchunk");
		return -1;
	}
	switch (section) {
	case LIMIT_SECTION:
		curlimit->byte_limit = result;
		break;
	case RULE_SECTION:
		currule->maxchunk = result;
		break;
	default: /* section == NONE_SECTION */
		maxchunk_global = result;
	}
	return 0;
}

/*
 * Parse "limit" section: get limit name.
 */
static int
parse_limit(char *s)
{
	int		i;
	struct limit	*lastlimit = curlimit;

	s = skip_spaces(skip_chars(s)); /* skip "limit[ \t]+" */
	SLIST_FOREACH(curlimit, &currule->limit_head, limit_entry)
		if (strcmp(s, curlimit->limitname) == 0) {
			line_err(s, "rule %s: duplicated \"limit %s\" section",
			    currule->rulename, s);
			return -1;
		}
	if ( (curlimit = calloc(1, sizeof *curlimit)) == NULL) {
		Syslog(LOG_ERR, "calloc: %m");
		return -1;
	}
	if (SLIST_EMPTY(&currule->limit_head))
		SLIST_INSERT_HEAD(&currule->limit_head, curlimit, limit_entry);
	else
		SLIST_INSERT_AFTER(lastlimit, curlimit, limit_entry);
	curlimit->fp = NULL;
	curlimit->filename = NULL;
	curlimit->reach.cmd = NULL;
	curlimit->reach.ncmd = 0;
	curlimit->zero_time_param.upto = UPTO_NOTSET;
	curlimit->expire.time.upto = UPTO_NOTSET;
	curlimit->expire.cmd = NULL;
	curlimit->rc[0].cmd = curlimit->rc[0].cmd_if_limit = curlimit->rc[0].cmd_if_nolimit = NULL;
	curlimit->rc[0].ncmd = curlimit->rc[0].ncmd_if_limit = curlimit->rc[0].ncmd_if_nolimit = 0;
	curlimit->rc[1].cmd = curlimit->rc[1].cmd_if_limit = curlimit->rc[1].cmd_if_nolimit = NULL;
	curlimit->rc[1].ncmd = curlimit->rc[1].ncmd_if_limit = curlimit->rc[1].ncmd_if_nolimit = 0;
	curlimit->info = NULL;
	curlimit->is_active = 1;
	curlimit->rule = currule;
	for (i = 0; i < 7; ++i) {
		curlimit->worktime[i].interval = NULL;
		curlimit->worktime[i].ninterval = 0;
	}
	if ( (curlimit->limitname = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	return 0;
}

/*
 * Parse "expired time" value.
 */
static int
parse_time_exp(char *s)
{
	char		*p = s;
	char		*endptr;
	int		level = 0, err = 0;
	u_int		value;
	struct time_exp	*texp;

	texp = section == LIMIT_SECTION ? &curlimit->zero_time_param : &curlimit->expire.time;
	texp->seconds = 0;
	texp->monthes = 0;
	texp->upto = UPTO_SIMPLE;
	for (;;) {
		p = skip_spaces(p);
		if (*p == '+') {
			++p;
			switch (*p) {
			case UPTO_dAY:
			case UPTO_DAY:
				texp->upto = UPTO_DAY;
				break;
			case UPTO_wEEK:
			case UPTO_WEEK:
				texp->upto = UPTO_WEEK;
				break;
			default: /* all other UPTO_xxx have only one syntax */
				texp->upto = *p;
			}
			++p;
			texp->side = texp->seconds > 0 ? 1 : 0;
		}
		if (*p == '\0')
			break;	/* EOL */
		if (Strtoui(&value, p, &endptr) < 0)
			return -1;
		p = endptr;
		switch (*p) {
		case 'M':
			if (level > 0)
				err = 1;
			else {
				level = 1;
				texp->monthes = value;
				value = 0;
			}
			break;
		case 'w':
		case 'W':
			if (level > 1)
				err = 1;
			else {
				level = 2;
				value *= WEEK;
			}
			break;
		case 'd':
		case 'D':
			if (level > 2)
				err = 1;
			else {
				level = 3;
				value *= DAY;
			}
			break;
		case 'h':
			if (level > 3)
				err = 1;
			else {
				level = 4;
				value *= HOUR;
			}
			break;
		case 'm':
			if (level > 4)
				err = 1;
			else {
				level = 5;
				value *= MINUTE;
			}
			break;
		default: /* 's' */
			if (level > 5)
				err = 1;
			else
				level = 6;
		}
		if (err) {
			line_err(p, "wrong time format");
			return -1;
		}
		if (texp->seconds > UINT_MAX - value) {
			line_err(p, "too big value for time format");
			return -1;
		}
		texp->seconds += value;
		++p;
	}
	if (section != EXPIRE_SECTION)
		if (texp->seconds == 0 && texp->monthes == 0 && texp->upto == UPTO_SIMPLE) {
			line_err(s, "parameter \"zero_time\" should be greater than zero");
			return -1;
		}
	return 0;
}

/*
 * Parse "exec" parameter.
 */
static int
parse_exec(char *q, char *s)
{
	char		*ptr, *start, bkp = '\0';
	short		uid_set = 0, uid_named = 0,
			gid_set = 0, gid_named = 0;
	u_int		*ncmdp_orig;
	u_long		uid, gid;
	int		*suppl_gid = NULL;
	u_int		nsuppl_gid, i;
	struct cmd	*cmdp, **cmdpp_orig;
	struct passwd	*pwd = NULL;
	struct group	*grp;
	
	s = skip_spaces(s);
	if (*s != '/' && only_abs_paths) {
		line_err(q, "parameter \"exec\": command should be given with absolute pathname, or set \"only_abs_paths\" parameter to \"no\"");
		return -1;
	}

	ptr = strchr(q, '(');
	if (ptr != NULL) { /*  exec(...) */
		start = ++ptr;
		if (*ptr != ':') {
			/* exec(user) or exec(user:group) */
			for (; *ptr != ')' && *ptr != ':'; ++ptr);
			bkp = *ptr;
			*ptr = '\0';
			if ( (pwd = getpwnam(start)) == NULL) {
				switch (fullstrtoul(&uid, start)) {
				case -1:
					return -1;
				case -2:
					line_err(q, "cannot find user \"%s\"", start);
					return -1;
				default:
					if ( (pwd = getpwuid(uid)) == NULL)
						if (bkp == ')') {
							line_err(q, "user with UID %lu was not found, such usage of \"exec\" parameter is prohibited", uid);
							return -1;
						}
				}
			} else {
				uid = pwd->pw_uid;
				uid_named = 1;
			}
			if (pwd && bkp != ':') {
				gid = pwd->pw_gid;
				if (parsing_mode != TEST_PARSING)
					gid_set = 1;
			}
			uid_set = 1;
			*ptr = bkp;
		}
		if (*ptr == ':') {
			start = ++ptr;
			if (*start != ')') {
				for (; *ptr != ')'; ++ptr);
				*ptr = '\0';
				if ( (grp = getgrnam(start)) == NULL) {
					switch (fullstrtoul(&gid, start)) {
					case -1:
						return -1;
					case -2:
						line_err(q, "cannot find group \"%s\"", start);
						return -1;
					}
				} else {
					gid = grp->gr_gid;
					gid_named = 1;
				}
				gid_set = 1;
			}
		}
		if (pwd != NULL && (bkp != ':' || (bkp == ':' && gid_set))) {
			u_int	nsuppl_gid_alloc;
			/* exec(user) or exec(user:group) */
			nsuppl_gid = nsuppl_gid_alloc = 5;
			if ( (suppl_gid = malloc(nsuppl_gid * sizeof *suppl_gid)) == NULL) {
				Syslog(LOG_ERR, "malloc: %m");
				return -1;
			}
			while (getgrouplist(pwd->pw_name, gid, suppl_gid, &nsuppl_gid) < 0) {
				nsuppl_gid = nsuppl_gid_alloc += 10;
				if ( (suppl_gid = realloc(suppl_gid, nsuppl_gid * sizeof *suppl_gid)) == NULL) {
					Syslog(LOG_ERR, "realloc: %m");
					free(suppl_gid);
					return -1;
				}
			}
			if (pwd->pw_gid != gid) {
				if (nsuppl_gid < nsuppl_gid_alloc) {
					suppl_gid[nsuppl_gid] = pwd->pw_gid;
					++nsuppl_gid;
				} else /* nsuppl_gid == nsuppl_gid_alloc */ {
					++nsuppl_gid;
					if ( (suppl_gid = realloc(suppl_gid, nsuppl_gid * sizeof *suppl_gid)) == NULL) {
						Syslog(LOG_ERR, "realloc: %m");
						free(suppl_gid);
						return -1;
					}
					suppl_gid[nsuppl_gid - 1] = pwd->pw_gid;
				}
			}
		} else if (gid_set) {
			nsuppl_gid = 1;
			if ( (suppl_gid = malloc(nsuppl_gid * sizeof *suppl_gid)) == NULL) {
				Syslog(LOG_ERR, "malloc: %m");
				return -1;
			}
			*suppl_gid = gid;
		}
	}

	if (parsing_mode == RECONFIG_PARSING &&
	    (section == STARTUP_SECTION || section_prev == STARTUP_SECTION))
		return 0;

	switch (section) {
	case REACH_SECTION:
		/* rule { limit { reach {}}} */
		cmdpp_orig = &curlimit->reach.cmd;
		ncmdp_orig = &curlimit->reach.ncmd;
		break;
	case EXPIRE_SECTION:
		/* rule { limit { expire {}}} */
		cmdpp_orig = &curlimit->expire.cmd;
		ncmdp_orig = &curlimit->expire.ncmd;
		break;
	case STARTUP_SECTION:
		switch (section_top) {
		case RULE_SECTION:
			/* rule { startup {}} */
			cmdpp_orig = &currule->rc[0].cmd;
			ncmdp_orig = &currule->rc[0].ncmd;
			break;
		case LIMIT_SECTION:
			/* rule { limit { startup {}}} */
			cmdpp_orig = &curlimit->rc[0].cmd;
			ncmdp_orig = &curlimit->rc[0].ncmd;
			break;
		default: /* NONE_SECTION */
			/* startup {} */
			cmdpp_orig = &startup_global.cmd;
			ncmdp_orig = &startup_global.ncmd;
		}
		break;
	case SHUTDOWN_SECTION:
		switch (section_top) {
		case RULE_SECTION:
			/* rule { shutdown {}} */
			cmdpp_orig = &currule->rc[1].cmd;
			ncmdp_orig = &currule->rc[1].ncmd;
			break;
		case LIMIT_SECTION:
			/* rule { limit { shutdown {}}} */
			cmdpp_orig = &curlimit->rc[1].cmd;
			ncmdp_orig = &curlimit->rc[1].ncmd;
			break;
		default: /* NONE_SECTION */
			/* shutdown {} */
			cmdpp_orig = &shutdown_global.cmd;
			ncmdp_orig = &shutdown_global.ncmd;
		}
		break;
	case IF_LIMIT_SECTION:
		if (section_top == RULE_SECTION) {
			if (section_prev == STARTUP_SECTION) {
				/* rule { startup { if_limit {}}} */
				cmdpp_orig = &currule->rc[0].cmd_if_limit;
				ncmdp_orig = &currule->rc[0].ncmd_if_limit;
			} else { /* section_prev == SHUTDOWN_SECTION */
				/* rule { shutdown { if_limit {}}} */
				cmdpp_orig = &currule->rc[1].cmd_if_limit;
				ncmdp_orig = &currule->rc[1].ncmd_if_limit;
			}
		} else /* section_top == LIMIT_SECTION */ {
			if (section_prev == STARTUP_SECTION) {
				/* rule { limit { startup { if_limit {}}}} */
				cmdpp_orig = &curlimit->rc[0].cmd_if_limit;
				ncmdp_orig = &curlimit->rc[0].ncmd_if_limit;
			} else { /* section_prev == SHUTDOWN_SECTION */
				/* rule { limit { shutdown { if_limit {}}}} */
				cmdpp_orig = &curlimit->rc[1].cmd_if_limit;
				ncmdp_orig = &curlimit->rc[1].ncmd_if_limit;
			}
		}
		break;
	default: /* section == IF_NOLIMIT_SECTION */
		if (section_top == RULE_SECTION) {
			if (section_prev == STARTUP_SECTION) {
				/* rule { startup { if_nolimit {}}} */
				cmdpp_orig = &currule->rc[0].cmd_if_nolimit;
				ncmdp_orig = &currule->rc[0].ncmd_if_nolimit;
			} else { /* section_prev == SHUTDOWN_SECTION */
				/* rule { shutdown { if_nolimit {}}} */
				cmdpp_orig = &currule->rc[1].cmd_if_nolimit;
				ncmdp_orig = &currule->rc[1].ncmd_if_nolimit;
			}
		} else { /* section_top == LIMIT_SECTION */
			if (section_prev == STARTUP_SECTION) {
				/* rule { limit { startup { if_nolimit {}}}} */
				cmdpp_orig = &curlimit->rc[0].cmd_if_nolimit;
				ncmdp_orig = &curlimit->rc[0].ncmd_if_nolimit;
			} else { /* section_prev == SHUTDOWN_SECTION */
				/* rule { limit { shutdown { if_nolimit {}}}} */
				cmdpp_orig = &curlimit->rc[1].cmd_if_nolimit;
				ncmdp_orig = &curlimit->rc[1].ncmd_if_nolimit;
			}
		}
	}
	if ( (cmdp = realloc(*cmdpp_orig, (*ncmdp_orig + 1) * sizeof *cmdp)) == NULL) {
		Syslog(LOG_ERR, "realloc: %m");
		free(suppl_gid);
		return -1;
	}
	*cmdpp_orig = cmdp;
	cmdp = *cmdpp_orig + *ncmdp_orig;
	++*ncmdp_orig;
	cmdp->uid = uid;
	cmdp->gid = gid;
	cmdp->uid_set = uid_set; cmdp->uid_named = uid_named;
	cmdp->gid_set = gid_set; cmdp->gid_named = gid_named;
	if ( (cmdp->str = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		free(suppl_gid);
		return -1;
	}
	if (suppl_gid != NULL) {
		if ( (cmdp->suppl_gid = malloc(nsuppl_gid * sizeof(gid_t))) == NULL) {
			Syslog(LOG_ERR, "malloc: %m");
			return -1;
		}
		for (i = 0; i < nsuppl_gid; ++i)
			cmdp->suppl_gid[i] = suppl_gid[i];
		cmdp->nsuppl_gid = nsuppl_gid;
		free(suppl_gid);
	} else {
		cmdp->suppl_gid = NULL;
		cmdp->nsuppl_gid = 0;
	}
	return 0;
}

/*
 * Parse "info" parameter.
 */
static int
parse_info(char *s)
{
	char	*info;

	if ( (info = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	if (section == RULE_SECTION) {
		free(currule->info);
		currule->info = info;
	} else /* section == LIMIT_SECTION */ {
		free(curlimit->info);
		curlimit->info = info;
	}
	return 0;
}

#ifdef WITH_MYSQL
/*
 * Parse "whoname" parameter.
 */
static int
parse_whoname(char *s)
{
	char	*whoname;

	if ( (whoname = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	syslog(LOG_DEBUG, "parse_who: %s", whoname);
	free(currule->whoname);
	currule->whoname = whoname;
	return 0;
}

/*
 * Parse "who" parameter.
 */
static int
parse_who(char *s)
{
	u_int	who_id;

	if ( (who_id = atoi(s)) == NULL) {
		Syslog(LOG_ERR, "atoi: %m");
		return -1;
	}
	currule->who = who_id;
	return 0;
}

/*
 * Parse "row" parameter.
 */
static int
parse_row(char *s)
{

	syslog(LOG_DEBUG, "parse_row: %s", s);

	if (strcmp(s,"in") == 0) currule->row = 1;
	else {
	if (strcmp(s,"out") == 0) currule->row = 2;
	     else currule->row = 0;
	}

	return 0;
}
#endif

/*
 * Parse "db_group" parameter.
 */
static int
parse_db_group(char *s)
{
	int		group_named = 0;
	u_long		gid;
	struct group	*grp;
	struct db_group	*ptr;

	if ( (grp = getgrnam(s)) == NULL)
		switch (fullstrtoul(&gid, s)) {
		case -1:
			return -1;
		case -2:
			line_err((char *)NULL, "cannot find group \"%s\"", s);
			return -1;
		}
	else {
		group_named = 1;
		gid = grp->gr_gid;
	}
	if (section == GLOBAL_SECTION)
		ptr = &db_group_global;
	else
		ptr = &currule->db_group;
	ptr->group_id = gid;
	ptr->group_set = 1;
	ptr->dir_mode = DB_DIR_PERM_UG;
	ptr->file_mode = DB_FILE_PERM_UG;
	ptr->group_named = group_named;
	return 0;
}

/*
 * Parse "db_dir" parameter.
 */
static int
parse_db_dir(char *s)
{
	if (*s != '/') {
		line_err(s, "directory in \"db_dir\" parameter should be given with absolute pathname");
		return -1;
	}
	free(db_dir);
	if ( (db_dir = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	return 0;
}

#ifdef WITH_MYSQL
/*
 * Parse "sql_name" parameter.
 */
static int
parse_sql_name(char *s){
       if (sql_name_set)
               free(sql_name);
       if ( (sql_name = strdup(s)) == NULL) {
               Syslog(LOG_ERR, "strdup: %m");
               return -1;
       }
       sql_name_set = 1;
       return 0;
}

/*
 * Parse "sql_user" parameter.
 */
static int
parse_sql_user(char *s){
       if (sql_user_set)
               free(sql_user);
       if ( (sql_user = strdup(s)) == NULL) {
               Syslog(LOG_ERR, "strdup: %m");
               return -1;
       }
       sql_user_set = 1;
       return 0;
}

/*
 * Parse "sql_pswd" parameter.
 */
static int
parse_sql_pswd(char *s){
       if (sql_pswd_set)
               free(sql_pswd);
       if ( (sql_pswd = strdup(s)) == NULL) {
               Syslog(LOG_ERR, "strdup: %m");
               return -1;
       }
       sql_pswd_set = 1;
       return 0;
}

/*
 * Parse "sql_host" parameter.
 */
static int
parse_sql_host(char *s){
       if (sql_host_set)
               free(sql_host);
       if ( (sql_host = strdup(s)) == NULL) {
               Syslog(LOG_ERR, "strdup: %m");
               return -1;
       }
       sql_host_set = 1;
       return 0;
}

/*
 * Parse "sql_port" parameter.
 */
static int
parse_sql_port(char *s){
       if (sql_port_set)
               sql_port = 0;
       if ( (sql_port = atoi(s)) == NULL) {
               Syslog(LOG_ERR, "atoi: %m");
               return -1;
       }
       sql_port_set = 1;
       return 0;
}
#endif /* WITH_MYSQL */

/*
 * Parse "worktime" parameter.
 */
static int
parse_worktime(char *s)
{
	int		wday;
	u_short		h1, m1, h2, m2, h2_prev, m2_prev;
	struct interval	*intp;
	struct worktime	*wtp;

	use_worktime = 1;
	switch (section) {
	case RULE_SECTION:
		currule->use_worktime = currule->use_rule_worktime = 1;
		currule->is_active = 0;
		wtp = currule->worktime;
		break;
	case LIMIT_SECTION:
		currule->use_worktime = curlimit->use_worktime = 1;
		curlimit->is_active = 0;
		wtp = curlimit->worktime;
		break;
	default: /* GLOBAL_SECTION */
		wtp = worktime_global;
		worktime_global_set = 1;
	}
	for (;;) {
		switch (*s) {
		case 's':
		case 'S':
			wday = 0;
			break;
		case 'm':
		case 'M':
			wday = 1;
			break;
		case 't':
		case 'T':
			wday = 2;
			break;
		case 'w':
		case 'W':
			wday = 3;
			break;
		case 'h':
		case 'H':
			wday = 4;
			break;
		case 'f':
		case 'F':
			wday = 5;
			break;
		default: /* 'a' || 'A' */
			wday = 6;
		}
		if (wtp[wday].interval != NULL) {
			wrong_format_msg(s, "worktime", "each day should be specified only one time");
			return -1;
		}
		h2_prev = m2_prev = 0;
		++s;
		for (;;) {
			s = skip_spaces(s);
			if (*s == '\0')
				return 0;	/* EOL */
			if (*s == '*') {
				h1 = m1 = m2 = 0;
				h2 = 24;
			} else {
				if (isdigit(*s) == 0)
					/* Next day in worktime. */
					break;
				errno = 0;
				if (sscanf(s, "%hu:%hu-%hu:%hu", &h1, &m1, &h2, &m2) != 4) {
					line_err(s, "sscanf(%s, \"%%hu:%%hu-%%hu:%%hu\"): failed: %m", s);
					return -1;
				}
				if ((h1 > 23 || h2 > 23 || m1 > 59 || m2 > 59) && !(h2 == 24 && m2 == 0)) {
					wrong_format_msg(s, "worktime", "wrong value of hours or minutes");
					return -1;
				}
				if ((h1 * HOUR + m1) > (h2 * HOUR + m2)) {
					wrong_format_msg(s, "worktime", "wrong time interval");
					return -1;
				}
				if (h1 == h2 && m1 == m2) {
					wrong_format_msg(s, "worktime", "zero seconds time intervals are not allowed");
					return -1;
				}
				if ((h2_prev * HOUR + m2_prev) > (h1 * HOUR + m1)) {
					wrong_format_msg(s, "worktime", "unsuccessive time interval");
					return -1;
				}
			}
			h2_prev = h2;
			m2_prev = m2;
			if ( (wtp[wday].interval = realloc(wtp[wday].interval,
			    (wtp[wday].ninterval + 1) * sizeof(struct interval))) == NULL) {
				Syslog(LOG_ERR, "realloc: %m");
				return -1;
			}
			intp = wtp[wday].interval + wtp[wday].ninterval;
			intp->h1 = h1;
			intp->m1 = m1;
			intp->h2 = h2;
			intp->m2 = m2;
			intp->sec1 = h1 * HOUR + m1 * MINUTE;
			intp->sec2 = h2 * HOUR + m2 * MINUTE;
			++wtp[wday].ninterval;
			s = skip_chars(s);
		}
	}
	/* NOTREACHED */
}

/*
 * Parse "debug_*" parameter.
 */
static int
parse_debug_level(int *result, char *s)
{
	long	level;

	switch (fullstrtoul(&level, s)) {
	case -1:
		return -1;
	case -2:
		line_err(s, "wrong format of debug level");
		return -1;
	}
	if (level > 3) {
		line_err(s, "too big debug level");
		return -1;
	}
	if (level < 0) {
		line_err(s, "incorrect debug level");
		return -1;
	}
	*result = level;
	return 0;
}

/*
 * Parse "yes/no" value.
 */
static int
parse_yesno(char *s)
{
	switch (*s) {
	case 'y':
	case 'Y':
		return 1;
	default:
		return 0;
	}
	/* NOTREACHED */
}

/*
 * Parse "file" parameter.
 */
static int
parse_file(char *q, char *s)
{
	struct include	*incp;

	if (*s != '/') {
		line_err(s, "include section: file should be given with absolute pathname");
		return -1;
	}
	if ( (incp = realloc(include, (ninclude + 1) * sizeof *include)) == NULL) {
		Syslog(LOG_ERR, "realloc: %m");
		return -1;
	}
	include = incp;
	incp += ninclude;
	++ninclude;
	incp->question = strchr(q, '(') == NULL ? 0 : 1;
	incp->use_re = 0;
	incp->dir = NULL;
	if ( (incp->file = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	return 0;
}

/*
 * Parse "files" parameter.
 */
static int
parse_files(char *q, char *s)
{
	int		question;
	char		*ptr, *start;
	struct include	*incp;

	ptr = skip_spaces(strchr(q, '(') + 1);
	if (*ptr == '?') {
		question = 1;
		ptr = strchr(ptr, '(') + 1;
	} else {
		if (*(ptr - 1) != '(')
			--ptr;
		question = 0;
	}
	start = ptr;
	if (*start != '/') {
		line_err(q, "include section: a directory should be given with the absolute pathname");
		return -1;
	}
	ptr = strrchr(start, ')');
	*ptr = '\0';
	if ( (incp = realloc(include, (ninclude + 1) * sizeof *include)) == NULL) {
		Syslog(LOG_ERR, "realloc: %m");
		return -1;
	}
	include = incp;
	incp += ninclude;
	++ninclude;
	incp->file = NULL;
	if ( (incp->dir = strdup(start)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	*ptr = ')';
	incp->use_re = 0;
	if ( (re_errcode = regcomp(&incp->re, s, REG_EXTENDED|REG_NOSUB)) != 0) {
		re_form_errbuf();
		line_err(q, "cannot recognize (compile) regular expression: regcomp(\"%s\"): %s",
		    s, re_errbuf);
		return -1;
	}
	incp->use_re = 1;
	if ( (incp->file = strdup(s)) == NULL) {
		Syslog(LOG_ERR, "strdup: %m");
		return -1;
	}
	incp->question = question;
	return 0;
}

/*
 * Parse "lock_wait_time" parameter.
 */
static int
parse_lock_wait_time(char *s)
{
	if (parse_time(s, &lock_wait_time) < 0)
		return -1;
	if (lock_wait_time == 0) {
		wrong_format_msg(s, "lock_wait_time", "should be greater than 0 seconds");
		return -1;
	}
	return 0;
}

/*
 * Skip variable and '=' sign from string.
 */
static char *
skip_var(char *s)
{
	char	*ptr = strchr(s, '=');

	return ptr != NULL ? ptr + 1 : NULL;
}

#if defined(WITH_IPFW) || defined(WITH_IP6FW)
/*
 * Compare two struct ipfwac.
 */
static int
cmp_ipfwac(const void *p1, const void *p2)
{
	const struct ipfwac	*q1 = p1, *q2 = p2;

	if (q1->number > q2->number)
		return 1;
	if (q1->number < q2->number)
		return -1;
	return q1->subnumber > q2->subnumber ? 1 : -1;
}
#endif /* defined(WITH_IPFW) || defined(WITH_IP6FW) */

#ifdef WITH_IPFW
/*
 * Sort ipfwac list for currule.
 */
static void
sort_ipfwac(void)
{
	qsort(currule->ipfwac, currule->nipfwac, sizeof *currule->ipfwac, cmp_ipfwac);
}
#endif /* WITH_IPFW */

#ifdef WITH_IP6FW
/*
 * Sort ip6fwac list for currule.
 */
static void
sort_ip6fwac(void)
{
	qsort(currule->ip6fwac, currule->nip6fwac, sizeof *currule->ip6fwac, cmp_ipfwac);
}
#endif /* WITH_IP6FW */

#ifdef WITH_IPFIL
/*
 * Compare two struct ipfilac.
 */
static int
cmp_ipfilac_group(const void *p1, const void *p2)
{
	return ((const struct ipfilac_group *)p1)->group_number >
	       ((const struct ipfilac_group *)p2)->group_number ? 1 : -1;
}

/*
 * Compare two ipfilac lists.
 */
static int
cmp_ipfilac_rule(const void *p1, const void *p2)
{
	return ((const struct ipfilac_rule *)p1)->rule_number >
	       ((const struct ipfilac_rule *)p2)->rule_number ? 1 : -1;
}

/*
 * Sort ipfilac lists for currule.
 */
static void
sort_ipfilac(struct ipfilac *ipfilacp)
{
	u_int		i;
	struct ipfilac_group	*groupp;

	qsort(ipfilacp->group, ipfilacp->ngroup, sizeof *ipfilacp->group, cmp_ipfilac_group);
	for (i = 0, groupp = ipfilacp->group; i < ipfilacp->ngroup; ++groupp, ++i)
		qsort(groupp->rule, groupp->nrule, sizeof *groupp->rule, cmp_ipfilac_rule);
}
#endif /* WITH_IPFIL */

#ifdef WITH_PF
/*
 * Compare two struct pfac.
 */
static int
cmp_pfac(const void *p1, const void *p2)
{
	return ((struct pfac *)p1)->number >
	       ((struct pfac *)p2)->number ? 1 : -1;
}

/*
 * Sort pfac list for currule.
 */
static void
sort_pfac(void)
{
	qsort(currule->pfac, currule->npfac, sizeof *currule->pfac, cmp_pfac);
}
#endif /* WITH_PF */

/*
 * Output error message for unexpected parameter or section in
 * configuration file.
 */
static void
isnot_expected_msg(const char *msg)
{
	line_err((char *)NULL, "\"%s\" is not expected here", msg);
}

/*
 * Check security for configuration file: absolute path, regular file,
 * owned by UID 0 (root), writeable only for user (root),
 * show warning message if file is readable by group or other user.
 */
static int
check_cfgfilename(void)
{
	struct stat	statbuf;

	if (parsing_mode != TEST_PARSING && *cfgfilename != '/') {
		Syslog(LOG_ERR, "configuration file should be given with absolute pathname: %s",
		    cfgfilename);
		return -1;
	}
	if (lstat(cfgfilename, &statbuf) < 0) {
		Syslog(LOG_ERR, "lstat(%s): %m", cfgfilename);
		return -1;
	}
	if (!S_ISREG(statbuf.st_mode)) {
		Syslog(LOG_ERR, "%s should be a regular file", cfgfilename);
		return -1;
	}
	if (parsing_mode != TEST_PARSING) {
		if (statbuf.st_uid != 0) {
			Syslog(LOG_ERR, "file %s should be owned by root", cfgfilename);
			return -1;
		}
		if (statbuf.st_mode & (S_IWGRP|S_IWOTH)) {
			Syslog(LOG_ERR, "file %s should not have write permissions for group or other users",
			    cfgfilename);
			return -1;
		}
		if (statbuf.st_mode & (S_IROTH|S_IROTH) && use_syslog)
			Syslog(LOG_INFO,  "file %s is readable by group and/or other users",
			    cfgfilename);
	}
	return 0;
}

/*
 * Read line from fp, return number of characters in line or
 * -1 if error occured. *size is equal to #bytes previously allocated in *strp
 * by malloc(). If there is not enough space in *strp, then readline()
 * reallocates *strp and updates *size.
 *
 * This is wrapper for fgets() function with some extensions.
 */
int
readline(char **strp, size_t *size, FILE *fp, const char *filename)
{
#define CHUNK_SIZE 100

/*
 * XXX CHUNK_SIZE can't be less than 1, because following code doesn't
 *     work with such value.
 */

#if (CHUNK_SIZE <= 1)
# error Macro CHUNK_SIZE should be greater than 1
#endif

	char		*s;
	size_t		can_nread;	/* #bytes to read in next fgets() */
	size_t		len;		/* length of read string */
	size_t		nread = 0;	/* how many bytes we read */

	if (*strp == NULL) {
		if ( (*strp = malloc(CHUNK_SIZE)) == NULL) {
			Syslog(LOG_ERR, "malloc(%u bytes): %m", CHUNK_SIZE);
			return -1;
		}
		*size = CHUNK_SIZE;
	}
	for (s = *strp, can_nread = *size; ;) {
		if (fgets(s, can_nread, fp) == NULL) {
			if (feof(fp) != 0) {
				++lineno;
				break;	/* EOF */
			}
			Syslog(LOG_ERR, "fgets(%s): %m", filename);
			return -1;
		}
		len = strlen(s);
		if (len > 0) {
			nread += len;
			if (s[len - 1] == '\n') {
				++lineno;
				if (len >= 2) {
					if (s[len - 2] == '\\') {
						s += len - 2;
						nread -= 2;
						can_nread -= len - 2;
						continue;
					} else
						break;
				} else
					break;
			}
		}
		if ( (s = realloc(*strp, *size + CHUNK_SIZE)) == NULL) {
			Syslog(LOG_ERR, "realloc(%u bytes): %m", *size + CHUNK_SIZE);
			return -1;
		}
		*strp = s;
		*size += can_nread = CHUNK_SIZE;
		s += nread;
	}
	return nread;
}

/*
 * Free all memory allocated for *include array.
 */
static void
free_include(void)
{
	u_int		i;
	struct include	*incp;

	for (i = 0, incp = include; i < ninclude; ++incp, ++i) {
		free(incp->file);
		if (incp->dir != NULL) {
			if (incp->use_re)
				regfree(&incp->re);
			free(incp->dir);
		}
	}
	include = NULL;
	ninclude = 0;
}

static void
free_worktime_global(void)
{
	int	i;

	for (i = 0; i < 7; ++i)
		free(worktime_global[i].interval);
}

/*
 * Main function for parsing whole configuration file.
 */
int
parse_config(int mode) 
{
	char		*buf = NULL, *string, *sp;
	short		startup_global_flag = 0, shutdown_global_flag = 0,
			startup_rule_flag = 0, shutdown_rule_flag = 0,
			startup_if_limit_rule_flag = 0, startup_if_nolimit_rule_flag = 0,
			shutdown_if_limit_rule_flag = 0, shutdown_if_nolimit_rule_flag = 0,
			startup_limit_flag = 0, shutdown_limit_flag = 0,
			startup_if_limit_limit_flag = 0, startup_if_nolimit_limit_flag = 0,
			shutdown_if_limit_limit_flag = 0, shutdown_if_nolimit_limit_flag = 0,
			expire_flag = 0, reach_flag = 0;
	size_t		bufsize;
	u_int		i, j;
	int		len;
	FILE		*fp = NULL;
	DIR		*dp = NULL;
	u_int		ninclude_curr = 0;
	ino_t		*include_inode = NULL, *ptr_inode;
	struct stat	statbuf;
	struct rule	*rule;
	struct include	*incp = NULL;

	if (mode == TEST_PARSING || mode == CMD_PARSING)
		use_syslog = 0;

	SLIST_INIT(&rule_head);
	ruleno = 0;
	db_dir = NULL;
#ifdef WITH_MYSQL
	sql_name_set = 0;
	sql_user = SQLUSER;
	sql_user_set = 0;
	sql_pswd = SQLPSWD;
	sql_pswd_set = 0;
	sql_host = SQLHOST;
	sql_host_set = 0;
	sql_port = SQLPORT;
	sql_port_set = 0;
#endif /* WITH_MYSQL */
	update_db_time_global = 0;
	append_db_time_global = 0;
	db_group_global.group_set = 0;
	db_group_global.group_named = 0;
	maxchunk_global = 0;
	only_abs_paths_set = 0;
	global_section_set = debug_section_set = include_section_set = 0;
	lock_db = 0;
	lock_db_set = 0;
	lock_wait_time = 0;
	only_abs_paths = 1;
	reset_debug();
	startup_global.cmd = startup_global.cmd_if_limit = startup_global.cmd_if_nolimit = NULL;
	startup_global.ncmd = startup_global.ncmd_if_limit = startup_global.ncmd_if_nolimit = 0;
	shutdown_global.cmd = shutdown_global.cmd_if_limit = shutdown_global.cmd_if_nolimit = NULL;
	shutdown_global.ncmd = shutdown_global.ncmd_if_limit = shutdown_global.ncmd_if_nolimit = 0;

	use_worktime = 0;
	worktime_global_set = 0;
	for (i = 0; i < 7; ++i) {
		worktime_global[i].interval = NULL;
		worktime_global[i].ninterval = 0;
	}

#ifdef WITH_IPFW
	use_ipfw = 0;
#endif
#ifdef WITH_IP6FW
	use_ip6fw = 0;
#endif
#ifdef WITH_IPFIL
	use_ipfil = use_ipfil_in = use_ipfil_out = 0;
#endif
#ifdef WITH_PF
	use_pf = 0;
#endif

	include = NULL;
	ninclude = nincluded = 0;

	section = section_top = section_prev = NONE_SECTION;

	parsing_mode = mode;
	if (build_config_regexes() < 0) {
		Syslog(LOG_ERR, "cannot build all regular expressions for configuration file parsing");
		goto parsing_failed;
	}

	cfgfilename = cfgfilename_main;
	if (use_syslog)
		syslog(LOG_INFO, "use configuration file %s, parsing...", cfgfilename);

	if (check_cfgfilename() < 0)
		goto parsing_failed;

	if ( (fp = fopen(cfgfilename, "r")) == NULL) {
		Syslog(LOG_ERR, "fopen(%s, \"r\"): %m", cfgfilename);
		goto parsing_failed;
	}

	if (mode == TEST_PARSING && testconfig > 1)
		printf("#\n#  Parse the configuration file %s\n#\n", cfgfilename);

	if ( (include_inode = malloc(sizeof *include_inode)) == NULL) {
		Syslog(LOG_ERR, "malloc: %m");
		goto parsing_failed;
	}
	if (lstat(cfgfilename, &statbuf) < 0) {
		Syslog(LOG_ERR, "lstat(%s): %m", cfgfilename);
		goto parsing_failed;
	}
	*include_inode = statbuf.st_ino;

	for (;;) {
		/* parse each configuration file, starting from default
		   configuration file or specified in the command line */
		lineno = 0;
		for (;;) {
			/* parse each line of configuration file */
			len = readline(&buf, &bufsize, fp, cfgfilename);
			if (len == 0 && feof(fp) != 0) {
				if (fclose(fp) != 0) {
					Syslog(LOG_ERR, "fclose(%s): %m", cfgfilename);
					fp = NULL;
					goto parsing_failed;
				}
				fp = NULL;
				if (section != NONE_SECTION) {
					line_err(buf, "unexpected end of the configuration file %s", cfgfilename);
					goto parsing_failed;
				}
				if (incp != NULL && (include + ninclude_curr)->use_re)
					free(cfgfilename);
				cfgfilename = NULL;
				if (ninclude_curr != ninclude &&
				    (mode != TEST_PARSING || (mode == TEST_PARSING && testconfig > 1)))
					/* there are some other files to be included */
					break;
end_of_parsing:
				if (nincluded > 0)
					if (use_syslog && debug_include > 0)
						syslog(LOG_INFO, "%d configuration file%s ha%s been included successfuly",
						    nincluded, nincluded > 1 ? "s" : "", nincluded > 1 ? "ve" : "s");
				if (mode != TEST_PARSING)
					free_include();
				free(buf);
				free(include_inode);
				if (mode != TEST_PARSING && mode != CMD_PARSING) {
					SLIST_FOREACH(rule, &rule_head, rule_entry) {
						if (rule->append_db_time == 0)
							rule->append_db_time = append_db_time_global;
						if (rule->maxchunk == 0)
							rule->maxchunk = maxchunk_global;
						if (rule->update_db_time > DAY ||
						    rule->append_db_time > DAY)
							syslog(LOG_INFO, "rule %s: \"update_db_time\" or \"append_db_time\" is greater than %u seconds (1 day), it is senseless",
							    rule->rulename, DAY);
						if (rule->update_db_time == 0)
							rule->update_db_time = update_db_time_global ? update_db_time_global : UPDATE_DB_TIME_DEF;
						if (rule->append_db_time != 0 && rule->update_db_time > rule->append_db_time)
							syslog(LOG_INFO, "rule %s: \"append_db_time\" is less than \"update_db_time\", it is senseless",
							    rule->rulename);
						if (!rule->db_group.group_set && db_group_global.group_set) {
							rule->db_group.group_id = db_group_global.group_id;
							rule->db_group.file_mode = db_group_global.file_mode;
							rule->db_group.dir_mode = db_group_global.dir_mode;
						}
						if (worktime_global_set && !rule->use_worktime) {
							rule->use_worktime = rule->use_rule_worktime = 1;
							rule->is_active = 0;
							for (j = 0; j < 7; ++j) {
								if (worktime_global[j].interval != NULL) {
									if ( (rule->worktime[j].interval = malloc(worktime_global[j].ninterval * sizeof(struct interval))) == NULL) {
										syslog(LOG_ERR, "malloc: %m");
										goto parsing_failed;
									}
									memcpy(rule->worktime[j].interval, worktime_global[j].interval, worktime_global[j].ninterval * sizeof(struct interval));
									rule->worktime[j].ninterval = worktime_global[j].ninterval;
								} else
									rule->worktime[j].interval = NULL;
							}
						}
					}
					free_worktime_global();
					if (lock_wait_time == 0)
						lock_wait_time = LOCK_WAIT_TIME_DEF;
					if (db_dir == NULL)
						db_dir = db_dir_default;
					if (ruleno == 0)
						syslog(LOG_WARNING, "cannot find any rule in the configuration file(s), hope that's OK");
					else
						syslog(LOG_INFO, "loaded %u accounting rule%s", ruleno, ruleno == 1 ? "" : "s");
				}
				return 0;
			}

			if (len < 0) {
				Syslog(LOG_ERR, "cannot read from the %s file", cfgfilename);
				goto parsing_failed;
			}
			if (len == 0)
				continue;
			if (buf[len - 1] == '\n')
				/* remove new line character '\n' */
				buf[len - 1] = '\0';
			if (buf[0] == '#' || buf[0] == ';')
				continue;	/* comment */
			if (REGEXEC(emptyline, buf) == 0)
				continue;	/* empty line */
			string = skip_spaces(buf);
			remove_trailing_spaces(string);
			if (section == NONE_SECTION) {
				len = strlen(string);
				if (string[len - 1] == '{') {
					string[len - 1] = '\0';
					remove_trailing_spaces(string);
				} else {
					line_err(buf, "expected begin of a section");
					goto parsing_failed;
				}
				if (REGEXEC(rule, string) == 0) {
					section = RULE_SECTION;
					startup_rule_flag = shutdown_rule_flag =
					    startup_if_limit_rule_flag =
					    startup_if_nolimit_rule_flag =
					    shutdown_if_limit_rule_flag =
					    shutdown_if_nolimit_rule_flag = 0;
					if (parse_rule(string) < 0)
						goto parsing_failed;
					continue;
				}
				if (strcmp(string, "global") == 0) {
					if (global_section_set) {
						line_err(string, "duplicated \"global\" section");
						goto parsing_failed;
					}
					global_section_set = 1;
					section = GLOBAL_SECTION;
					continue;
				}
				if (strcmp(string, "debug") == 0) {
					if (debug_section_set) {
						line_err(string, "duplicated \"debug\" section");
						goto parsing_failed;
					}
					debug_section_set = 1;
					section = DEBUG_SECTION;
					continue;
				}
				if (strcmp(string, "startup") == 0) {
					if (startup_global_flag != 0) {
						line_err(string, "duplicated \"startup\" section");
						goto parsing_failed;
					}
					startup_global_flag = 1;
					section = STARTUP_SECTION;
					continue;
				}
				if (strcmp(string, "shutdown") == 0) {
					if (shutdown_global_flag != 0) {
						line_err(string, "duplicated \"shutdown\" section");
						goto parsing_failed;
					}
					shutdown_global_flag = 1;
					section = SHUTDOWN_SECTION;
					continue;
				}
				if (strcmp(string, "include") == 0) {
					++include_section_set;
					section = INCLUDE_SECTION;
					continue;
				}
				line_err(string, "unexpected or unknown section");
				goto parsing_failed;
			}
			if (string[0] == '}' && string[1] == '\0') {
				/* end of section */
				switch (section) {
				case RULE_SECTION:
					if (1
#ifdef WITH_IPFW
					    && currule->ipfwac == NULL
#endif
#ifdef WITH_IP6FW
					    && currule->ip6fwac == NULL
#endif
#ifdef WITH_IPFIL
					    && currule->ipfilac_in.group == NULL
					    && currule->ipfilac_out.group == NULL
#endif
#ifdef WITH_PF
					    && currule->pfac == NULL
#endif
					) {
						line_err((char *)NULL, "rule %s: rule should have at least one accouting parameter",
						    currule->rulename);
						goto parsing_failed;
					}
#ifdef WITH_IPFW
					if (currule->ipfwac != NULL) 
						sort_ipfwac();
#endif
#ifdef WITH_IP6FW
					if (currule->ip6fwac != NULL)
						sort_ip6fwac();
#endif
#ifdef WITH_IPFIL
					if (currule->ipfilac_in.group != NULL)
						sort_ipfilac(&currule->ipfilac_in);
					if (currule->ipfilac_out.group != NULL)
						sort_ipfilac(&currule->ipfilac_out);
#endif
#ifdef WITH_PF
					if (currule->pfac != NULL)
						sort_pfac();
#endif
					section = NONE_SECTION;
					break;
				case GLOBAL_SECTION:
					section = NONE_SECTION;
#ifdef WITH_MYSQL
                                       if (!sql_name_set) {
                                           Syslog(LOG_ERR, "%s", cfgfilename);
                                           Syslog(LOG_ERR, "parameter \"sql_name\" in \"global\" section should be present");
                                           goto parsing_failed;
                                       }
#endif /* WITH_MYSQL */
					break;
				case LIMIT_SECTION:
					if (curlimit->byte_limit == 0) {
						Syslog(LOG_ERR, "%s", cfgfilename);
						Syslog(LOG_ERR, "rule %s, limit %s: parameter \"byte_limit\" in \"limit\" section should be present",
						    currule->rulename, curlimit->limitname);
						goto parsing_failed;
					}
					section = RULE_SECTION;
					break;
				case EXPIRE_SECTION:
					if (curlimit->expire.time.upto == UPTO_NOTSET) {
						Syslog(LOG_ERR, "%s", cfgfilename);
						Syslog(LOG_ERR, "rule %s, limit %s: parameter \"expire_time\" in \"expire\" section should be present",
						    currule->rulename, curlimit->limitname);
						goto parsing_failed;
					}
					section = LIMIT_SECTION;
					break;
				case STARTUP_SECTION:
					section = section_top;
					section_top = NONE_SECTION;
					break;
				case SHUTDOWN_SECTION:
					section = section_top;
					section_top = NONE_SECTION;
					break;
				case REACH_SECTION:
					section = LIMIT_SECTION;
					break;
				case IF_LIMIT_SECTION:
				case IF_NOLIMIT_SECTION:
					section = section_prev;
					section_prev = NONE_SECTION;
					break;
				default: /* DEBUG_SECTION || INCLUDE_SECTION */
					section = NONE_SECTION;
					break;
				}
				continue;
			}

			len = strlen(string);
			if (string[len - 1] == '{') {
				string[len - 1] = '\0';
				remove_trailing_spaces(string);
				if (REGEXEC(limit, string) == 0) {
					if (section != RULE_SECTION) {
						isnot_expected_msg("limit");
						goto parsing_failed;
					}
					startup_limit_flag = shutdown_limit_flag =
					    startup_if_limit_limit_flag =
					    startup_if_nolimit_limit_flag =
					    shutdown_if_limit_limit_flag =
					    shutdown_if_nolimit_limit_flag = expire_flag = reach_flag = 0;
					section = LIMIT_SECTION;
					if (parse_limit(string) < 0)
						goto parsing_failed;
					continue;
				}
				if (strcmp(string, "expire") == 0) {
					if (section != LIMIT_SECTION) {
						isnot_expected_msg("expire");
						goto parsing_failed;
					}
					if (expire_flag) {
						line_err(string, "rule %s, limit %s: duplicated \"expire\" section",
						    currule->rulename, curlimit->limitname);
						goto parsing_failed;
					}
					expire_flag = 1;
					section = EXPIRE_SECTION;
					continue;
				}
				if (strcmp(string, "reach") == 0) {
					if (section != LIMIT_SECTION) {
						isnot_expected_msg("reach");
						goto parsing_failed;
					}
					if (reach_flag) {
						line_err(string, "rule %s, limit %s: duplicated \"reach\" section",
						    currule->rulename, curlimit->limitname);
						goto parsing_failed;
					}
					reach_flag = 1;
					section = REACH_SECTION;
					continue;
				}
				if (strcmp(string, "startup") == 0) {
					if (section != RULE_SECTION && section != LIMIT_SECTION) {
						isnot_expected_msg("startup");
						goto parsing_failed;
					}
					if (section == RULE_SECTION) {
						if (startup_rule_flag) {
							line_err(string, "rule %s: duplicated \"startup\" section",
							    currule->rulename);
							goto parsing_failed;
						}
						startup_rule_flag = 1;
					} else { /* section == LIMIT_SECTION */
						if (startup_limit_flag) {
							line_err(string, "rule %s, limit %s: duplicated \"startup\" section",
							    currule->rulename, curlimit->limitname);
							goto parsing_failed;
						}
						startup_limit_flag = 1;
					}
					section_top = section;
					section = STARTUP_SECTION;
					continue;
				}
				if (strcmp(string, "shutdown") == 0) {
					if (section != RULE_SECTION && section != LIMIT_SECTION) {
						isnot_expected_msg("shutdown");
						goto parsing_failed;
					}
					if (section == RULE_SECTION) {
						if (shutdown_rule_flag) {
							line_err(string, "rule %s: duplicated \"shutdown\" section",
							    currule->rulename);
							goto parsing_failed;
						}
						shutdown_rule_flag = 1;
					} else { /* section == LIMIT_SECTION */
						if (shutdown_limit_flag) {
							line_err(string, "rule %s, limit %s: duplicated \"shutdown\" section",
							    currule->rulename, curlimit->limitname);
							goto parsing_failed;
						}
						shutdown_limit_flag = 1;
					}
					section_top = section;
					section = SHUTDOWN_SECTION;
					continue;
				}
				if (REGEXEC(if_limit, string) == 0) {
					if ((section != STARTUP_SECTION && section != SHUTDOWN_SECTION) ||
					    section_top == NONE_SECTION) {
						isnot_expected_msg("if_limit_is_reached");
						goto parsing_failed;
					}
					if (section_top == RULE_SECTION) {
						if (section == STARTUP_SECTION) {
							if (startup_if_limit_rule_flag) {
								line_err(string, "rule %s: duplicated \"if_limit_is_reached\" section in \"startup\" section",
								    currule->rulename);
								goto parsing_failed;
							}
							startup_if_limit_rule_flag = 1;
						} else { /* section == SHUTDOWN_SECTION */
							if (shutdown_if_limit_rule_flag) {
								line_err(string, "rule %s: duplicated \"if_limit_is_reached\" section in \"shutdown\" section",
								    currule->rulename);
								goto parsing_failed;
							}
							shutdown_if_limit_rule_flag = 1;
						}
					} else /* section_top == LIMIT_SECTION */ {
						if (section == STARTUP_SECTION) {
							if (startup_if_limit_limit_flag) {
								line_err(string, "rule %s, limit %s: duplicated \"if_limit_is_reached\" section in \"startup\" section",
								    currule->rulename, curlimit->limitname);
								goto parsing_failed;
							}
							startup_if_limit_limit_flag = 1;
						} else { /* section == SHUTDOWN_SECTION */
							if (shutdown_if_limit_limit_flag) {
								line_err(string, "rule %s, limit %s: duplicated \"if_limit_is_reached\" section in \"shutdown\" section",
								    currule->rulename, curlimit->limitname);
								goto parsing_failed;
							}
							shutdown_if_limit_limit_flag = 1;
						}
					}
					section_prev = section;
					section = IF_LIMIT_SECTION;
					continue;
				}
				if (REGEXEC(if_nolimit, string) == 0) {
					if ((section != STARTUP_SECTION && section != SHUTDOWN_SECTION) ||
					    section_top == NONE_SECTION) {
						isnot_expected_msg("if_limit_is_not_reached");
						goto parsing_failed;
					}
					if (section_top == RULE_SECTION) {
						if (section == STARTUP_SECTION) {
							if (startup_if_nolimit_rule_flag) {
								line_err(string, "rule %s: duplicated \"if_limit_is_not_reached\" section in \"startup\" section",
								    currule->rulename);
								goto parsing_failed;
							}
							startup_if_nolimit_rule_flag = 1;
						} else { /* section == SHUTDOWN_SECTION */
							if (shutdown_if_nolimit_rule_flag) {
								line_err(string, "rule %s: duplicated \"if_limit_is_not_reached\" section in \"shutdown\" section",
								    currule->rulename);
								goto parsing_failed;
							}
							shutdown_if_nolimit_rule_flag = 1;
						}
					} else /* section_top == LIMIT_SECTION */ {
						if (section == STARTUP_SECTION) {
							if (startup_if_nolimit_limit_flag) {
								line_err(string, "rule %s, limit %s: duplicated \"if_limit_is_not_reached\" section in \"startup\" section",
								    currule->rulename, curlimit->limitname);
								goto parsing_failed;
							}
							startup_if_nolimit_limit_flag = 1;
						} else { /* section == SHUTDOWN_SECTION */
							if (shutdown_if_nolimit_limit_flag) {
								line_err(string, "rule %s, limit %s: duplicated \"if_limit_is_not_reached\" section in \"shutdown\" section",
								    currule->rulename, curlimit->limitname);
								goto parsing_failed;
							}
							shutdown_if_nolimit_limit_flag = 1;
						}
					}
					section_prev = section;
					section = IF_NOLIMIT_SECTION;
					continue;
				}
				line_err(string, "unexpected or unknown section");
				goto parsing_failed;
			}

			if ( (sp = skip_var(string)) == NULL) {
				line_err(string, "unknown syntax, expected a parameter, beginning or ending of a section");
				goto parsing_failed;
			}
			*(sp - 1) = '\0'; /* '\0' -> '=' */
			remove_trailing_spaces(string);
			sp = skip_spaces(sp);
			if (REGEXEC(emptyline, sp) == 0) {
				line_err(string, "expected value for parameter");
				goto parsing_failed;
			}
			if (strcmp(string, "ipfw") == 0 || strcmp(string, "ip4fw") == 0) {
				if (section != RULE_SECTION) {
					isnot_expected_msg("ipfw");
					goto parsing_failed;
				}
#ifdef WITH_IPFW
				if (REGEXEC(ipfw_val, sp) != 0) {
					wrong_format_msg(sp, "ipfw", "");
					goto parsing_failed;
				}
				if (parse_ipfw(sp) < 0)
					goto parsing_failed;
#else
				line_err(string, "FreeBSD IP Firewall is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"ipfw\" parameter.");
				goto parsing_failed;
#endif /* WITH_IPFW */
			} else if (strcmp(string, "ip6fw") == 0) {
				if (section != RULE_SECTION) {
					isnot_expected_msg("ip6fw");
					goto parsing_failed;
				}
#ifdef WITH_IP6FW
				if (REGEXEC(ipfw_val, sp) != 0) {
					wrong_format_msg(sp, "ip6fw", "");
					goto parsing_failed;
				}
				if (parse_ip6fw(sp) < 0)
					goto parsing_failed;
#else
				line_err(string, "FreeBSD IPv6 Firewall is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"ip6fw\" parameter.");
				goto parsing_failed;
#endif /* WITH_IP6FW */
			} else if (strcmp(string, "ipfil") == 0) {
				if (section != RULE_SECTION) {
					isnot_expected_msg("ipfil");
					goto parsing_failed;
				}
#ifdef WITH_IPFIL
				if (REGEXEC(ipfil_val, sp) != 0) {
					wrong_format_msg(sp, "ipfil", "");
					goto parsing_failed;
				}
				if (parse_ipfil(sp) < 0)
					goto parsing_failed;
#else
				line_err(string, "IP Filter is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"ipfil\" parameter");
				goto parsing_failed;
#endif /* WITH_IPFIL */
			} else if (strcmp(string, "pf") == 0) {
				if (section != RULE_SECTION) {
					isnot_expected_msg("pf");
					goto parsing_failed;
				}
#ifdef WITH_PF
				if (REGEXEC(pf_val, sp) != 0) {
					wrong_format_msg(sp, "pf", "");
					goto parsing_failed;
				}
				if (parse_pf(sp) < 0)
					goto parsing_failed;
#else
				line_err(string, "OpenBSD Packet Filter is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"pf\" parameter.");
				goto parsing_failed;
#endif /* WITH_PF */
			} else if (strcmp(string, "update_db_time") == 0) {
				if (section != RULE_SECTION && section != GLOBAL_SECTION) {
					isnot_expected_msg("update_db_time");
					goto parsing_failed;
				}
				if (REGEXEC(time_val, sp) != 0) {
					wrong_format_msg(sp, "update_db_time", "");
					goto parsing_failed;
				}
				if (parse_update_db_time(sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "append_db_time") == 0) {
				if (section != RULE_SECTION && section != GLOBAL_SECTION) {
					isnot_expected_msg("append_db_time");
					goto parsing_failed;
				}
				if (REGEXEC(time_val, sp) != 0) {
					wrong_format_msg(sp, "append_db_time", "");
					goto parsing_failed;
				}
				if (parse_append_db_time(sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "byte_limit") == 0 || strcmp(string, "bytes_limit") == 0) {
				if (section != LIMIT_SECTION) {
					isnot_expected_msg("byte_limit");
					goto parsing_failed;
				}
				if (REGEXEC(size_val, sp) != 0) {
					wrong_format_msg(sp, "byte_limit", "");
					goto parsing_failed;
				}
				if (parse_size(sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "zero_time") == 0) {
				if (section != LIMIT_SECTION) {
					isnot_expected_msg("zero_time");
					goto parsing_failed;
				}
				if (REGEXEC(time_exp_val, sp) != 0) {
					wrong_format_msg(sp, "zero_time", "");
					goto parsing_failed;
				}
				if (parse_time_exp(sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "expire_time") == 0) {
				if (section != EXPIRE_SECTION) {
					isnot_expected_msg("expire_time");
					goto parsing_failed;
				}
				if (REGEXEC(time_exp_val, sp) != 0) {
					wrong_format_msg(sp, "expire_time", "");
					goto parsing_failed;
				}
				if (parse_time_exp(sp) < 0)
					goto parsing_failed;
			} else if (REGEXEC(exec, string) == 0) {
				if (section != REACH_SECTION && section != EXPIRE_SECTION &&
				    section != STARTUP_SECTION && section != IF_LIMIT_SECTION &&
				    section != IF_NOLIMIT_SECTION && section != SHUTDOWN_SECTION) {
					isnot_expected_msg("exec");
					goto parsing_failed;
				}
				if (parse_exec(string, sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "maxchunk") == 0) {
				if (section != RULE_SECTION && section != GLOBAL_SECTION) {
					isnot_expected_msg("maxchunk");
					goto parsing_failed;
				}
				if (REGEXEC(size_val, sp) != 0) {
					wrong_format_msg(sp, "maxchunk", "");
					goto parsing_failed;
				}
				if (parse_size(sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "info") == 0) {
				if (section != RULE_SECTION && section != LIMIT_SECTION) {
					isnot_expected_msg("info");
					goto parsing_failed;
				}
				if (parse_info(sp) < 0)
					goto parsing_failed;
			}
#ifdef WITH_MYSQL
			  else if (strcmp(string, "who") == 0) {
				if (section != RULE_SECTION) {
					isnot_expected_msg("who");
					goto parsing_failed;
				}
/*
                               if (REGEXEC(sql_port, sp) != 0) {
                                       wrong_format_msg(sp, "who", "only integer <= 99999 is possible");
                                       goto parsing_failed;
                               }
*/
				if (parse_whoname(sp) < 0)
					goto parsing_failed;
			}
			  else if (strcmp(string, "row") == 0) {
				if (section != RULE_SECTION) {
					isnot_expected_msg("row");
					goto parsing_failed;
				}
/*
                               if (REGEXEC(sql_port, sp) != 0) {
                                       wrong_format_msg(sp, "who", "only integer <= 99999 is possible");
                                       goto parsing_failed;
                               }
*/
				if (parse_row(sp) < 0)
					goto parsing_failed;
			}

#endif
			  else if (strcmp(string, "db_group") == 0) {
				if (section != GLOBAL_SECTION && section != RULE_SECTION) {
					isnot_expected_msg("db_group");
					goto parsing_failed;
				}
				if (REGEXEC(db_group_val, sp) != 0) {
					wrong_format_msg(sp, "db_group", "");
					goto parsing_failed;
				}
				if (parse_db_group(sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "worktime") == 0) {
				if (section != GLOBAL_SECTION && section != RULE_SECTION &&
				    section != LIMIT_SECTION) {
					isnot_expected_msg("worktime");
					goto parsing_failed;
				}
				if (REGEXEC(worktime_val, sp) != 0) {
					wrong_format_msg(sp, "worktime", "");
					goto parsing_failed;
				}
				if (parse_worktime(sp) < 0)
					goto parsing_failed;
			} else if (strcmp(string, "db_dir") == 0) {
				if (section != GLOBAL_SECTION) {
					isnot_expected_msg("db_dir");
					goto parsing_failed;
				}
				if (parse_db_dir(sp) < 0)
					goto parsing_failed;
			}
#ifdef WITH_MYSQL
                        else if (strcmp(string, "sql_name") == 0) {
                               if (section != GLOBAL_SECTION) {
                                       isnot_expected_msg("sql_name");
                                       goto parsing_failed;
                               }
                               if (parse_sql_name(sp) < 0)
                                       goto parsing_failed;
                       } else if (strcmp(string, "sql_user") == 0) {
                               if (section != GLOBAL_SECTION) {
                                       isnot_expected_msg("sql_user");
                                       goto parsing_failed;
                               }
                               if (parse_sql_user(sp) < 0)
                                       goto parsing_failed;
                       } else if (strcmp(string, "sql_pswd") == 0) {
                               if (section != GLOBAL_SECTION) {
                                       isnot_expected_msg("sql_pswd");
                                       goto parsing_failed;
                               }
                               if (parse_sql_pswd(sp) < 0)
                                       goto parsing_failed;
                       } else if (strcmp(string, "sql_host") == 0) {
                               if (section != GLOBAL_SECTION) {
                                       isnot_expected_msg("sql_host");
                                       goto parsing_failed;
                               }
                               if (parse_sql_host(sp) < 0)
                                       goto parsing_failed;
                       } else if (strcmp(string, "sql_port") == 0) {
                               if (section != GLOBAL_SECTION) {
                                       isnot_expected_msg("sql_port");
                                       goto parsing_failed;
                               }
                               if (REGEXEC(sql_port, sp) != 0) {
                                       wrong_format_msg(sp, "sql_port", "only integer <= 99999 is possible");
                                       goto parsing_failed;
                               }
                               if (parse_sql_port(sp) < 0)
                                       goto parsing_failed;
                       }
#endif /* WITH_MYSQL */
			  else if (strcmp(string, "debug_exec") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_exec");
					goto parsing_failed;
				}
				if (parse_debug_level(&debug_exec, sp) < 0)
					goto parsing_failed;
				debug_exec_set = 1;
			} else if (strcmp(string, "debug_limit") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_limit");
					goto parsing_failed;
				}
				if (parse_debug_level(&debug_limit, sp) < 0)
					goto parsing_failed;
				debug_limit_set = 1;
			} else if (strcmp(string, "debug_ipfw") == 0 || strcmp(string, "debug_ip4fw") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_ipfw");
					goto parsing_failed;
				}
#ifdef WITH_IPFW
				if (parse_debug_level(&debug_ipfw, sp) < 0)
					goto parsing_failed;
				debug_ipfw_set = 1;
#else
				line_err(string, "FreeBSD IP Firewall is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"debug_ipfw\" parameter.");
				goto parsing_failed;
#endif /* WITH_IPFW */
			} else if (strcmp(string, "debug_ip6fw") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_ip6fw");
					goto parsing_failed;
				}
#ifdef WITH_IP6FW
				if (parse_debug_level(&debug_ip6fw, sp) < 0)
					goto parsing_failed;
				debug_ip6fw_set = 1;
#else
				line_err(string, "FreeBSD IPv6 Firewall is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"debug_ip6fw\" parameter.");
				goto parsing_failed;
#endif /* WITH_IP6FW */
			} else if (strcmp(string, "debug_ipfil") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_ipfil");
					goto parsing_failed;
				}
#ifdef WITH_IPFIL
				if (parse_debug_level(&debug_ipfil, sp) < 0)
					goto parsing_failed;
				debug_ipfil_set = 1;
#else
				line_err(string, "IP Filter is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"debug_ipfil\" parameter.");
				goto parsing_failed;
#endif /* WITH_IPFIL */
			} else if (strcmp(string, "debug_pf") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_pf");
					goto parsing_failed;
				}
#ifdef WITH_PF
				if (parse_debug_level(&debug_pf, sp) < 0)
					goto parsing_failed;
				debug_pf_set = 1;
#else
				line_err(string, "OpenBSD Packet Filter is not supported or was disabled during compilation process.");
				line_err((char *)NULL, "Do not use \"debug_pf\" parameter.");
				goto parsing_failed;
#endif /* WITH_PF */
			} else if (strcmp(string, "debug_time") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_time");
					goto parsing_failed;
				}
				if (parse_debug_level(&debug_time, sp) < 0)
					goto parsing_failed;
				debug_time_set = 1;
			} else if (strcmp(string, "debug_worktime") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_worktime");
					goto parsing_failed;
				}
				if (parse_debug_level(&debug_worktime, sp) < 0)
					goto parsing_failed;
				debug_worktime_set = 1;
			} else if (strcmp(string, "debug_lock") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_lock");
					goto parsing_failed;
				}
				if (parse_debug_level(&debug_lock, sp) < 0)
					goto parsing_failed;
				debug_lock_set = 1;
			} else if (strcmp(string, "debug_include") == 0) {
				if (section != DEBUG_SECTION) {
					isnot_expected_msg("debug_include");
					goto parsing_failed;
				}
				if (parse_debug_level(&debug_include, sp) < 0)
					goto parsing_failed;
				debug_include_set = 1;
			} else if (strcmp(string, "lock_db") == 0) {
				if (section != GLOBAL_SECTION) {
					isnot_expected_msg("lock_db");
					goto parsing_failed;
				}
				if (REGEXEC(yesno_val, sp) != 0) {
					wrong_format_msg(sp, "lock_db", "");
					goto parsing_failed;
				}
				lock_db = parse_yesno(sp);
				lock_db_set = 1;
			} else if (strcmp(string, "lock_wait_time") == 0) {
				if (section != GLOBAL_SECTION) {
					isnot_expected_msg("lock_wait_time");
					goto parsing_failed;
				}
				if (REGEXEC(time_val, sp) != 0) {
					wrong_format_msg(sp, "lock_wait_time", "");
					goto parsing_failed;
				}
				if (parse_lock_wait_time(sp) < 0)
					goto parsing_failed;
				if (mode != TEST_PARSING && mode != CMD_PARSING && lock_wait_time > MINUTE)
					Syslog(LOG_WARNING, "value for parameter \"lock_wait_time\" greater than 1 minute is not recommended");
			} else if (strcmp(string, "only_abs_paths") == 0 || strcmp(string, "only_abs_path") == 0) {
				if (section != GLOBAL_SECTION) {
					isnot_expected_msg("only_abs_paths");
					goto parsing_failed;
				}
				if (REGEXEC(yesno_val, sp) != 0) {
					wrong_format_msg(sp, "only_abs_paths", "");
					goto parsing_failed;
				}
				only_abs_paths = parse_yesno(sp);
				only_abs_paths_set = 1;
			} else if (REGEXEC(file, string) == 0) {
				if (section != INCLUDE_SECTION) {
					isnot_expected_msg("file");
					goto parsing_failed;
				}
				if (parse_file(string, sp) < 0)
					goto parsing_failed;
			} else if (REGEXEC(files, string) == 0) {
				if (section != INCLUDE_SECTION) {
					isnot_expected_msg("files");
					goto parsing_failed;
				}
				if (parse_files(string, sp) < 0)
					goto parsing_failed;
			} else {
				line_err(string, "unknown parameter or syntax");
				goto parsing_failed;	
			}
		}

		while (include != NULL) {
			u_int		k;

			/* "include" section was used */
			if (incp == NULL) {
				if (mode == TEST_PARSING)
					printf("#  Including configuration files:\n");
				else if (use_syslog && debug_include > 0)
					syslog(LOG_INFO, "including configuration files:");
			} else {
				if (((include + ninclude_curr)->use_re == 0 || dp == NULL) && ++ninclude_curr == ninclude)
					goto end_of_parsing;
			}
			incp = include + ninclude_curr;
			if (incp->use_re) {
				/* "files" parameter */
				struct dirent	*dirp;

				if (dp == NULL) {
					/* need to open a directory */
					if (lstat(incp->dir, &statbuf) < 0) {
						/* can't lstat dir */
						if (errno != ENOENT) {
							Syslog(LOG_ERR, "lstat(%s): %m", incp->dir);
							goto parsing_failed;
						}
						/* no such dir */
						if (incp->question) {
							if (mode == TEST_PARSING)
								printf("#  |--<n> %s\n", incp->dir);
							else if (use_syslog && debug_include > 1)
								syslog(LOG_INFO, "|--<n> %s", incp->dir);
							continue; /* include next file or directory */
						} else {
							Syslog(LOG_ERR, "lstat(%s): %m", incp->dir);
							goto parsing_failed;
						}
					} else {
						/* dir is present */
						if (!S_ISDIR(statbuf.st_mode)) {
							Syslog(LOG_ERR, "%s is expected to be a directory", incp->dir);
							goto parsing_failed;
						}
						if (mode != TEST_PARSING) {
							if (statbuf.st_uid != 0) {
								Syslog(LOG_ERR, "directory %s should be owned by root", incp->dir);
								goto parsing_failed;
							}
							if (statbuf.st_mode & (S_IWGRP|S_IWOTH)) {
								Syslog(LOG_ERR, "directory %s should not have write permissions for group and other users",
								    incp->dir);
								goto parsing_failed;
							}
						}
						if ( (dp = opendir(incp->dir)) != NULL) {
							/* dir is opened */
							if (mode == TEST_PARSING)
								printf("#  |--<+> %s (RE %s)\n", incp->dir, incp->file);
							else if (use_syslog && debug_include > 0)
								syslog(LOG_INFO, "|--<+> %s (RE %s)", incp->dir, incp->file);
						} else {
							/* can't open dir */
							Syslog(LOG_ERR, "opendir(%s): %m", incp->dir);
							goto parsing_failed;
						}
					}
				}
				/* dir was opened and is ready for scanning */
				for (;;) {
					if ( (dirp = readdir(dp)) == NULL) {
						if (closedir(dp) < 0) {
							dp = NULL;
							Syslog(LOG_ERR, "closedir(%s): %m", incp->dir);
							goto parsing_failed;
						}
						dp = NULL;
						break; /* include next file or directory */
					}
					if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
						continue; /* include next file */
					if (regexec(&incp->re, dirp->d_name, 0, (regmatch_t *)NULL, 0) != 0) {
						if (mode == TEST_PARSING)
							printf("#  |   |--[!] %s\n", dirp->d_name);
						else if (use_syslog && debug_include > 1)
							syslog(LOG_INFO, "|   |--[!] %s", dirp->d_name);
						continue; /* include next file */
					}
					if (asprintf(&cfgfilename, "%s/%s", incp->dir, dirp->d_name) < 0) {
						Syslog(LOG_ERR, "asprintf: %m");
						goto parsing_failed;
					}
					if (lstat(cfgfilename, &statbuf) < 0) {
						Syslog(LOG_ERR, "lstat(%s): %m", cfgfilename);
						goto parsing_failed;
					}
					for (k = 0; k < nincluded + 1; ++k)
						if (statbuf.st_ino == include_inode[k]) {
							if (mode == TEST_PARSING)
								printf("#  |   |--[i] %s\n", dirp->d_name);
							else if (use_syslog && debug_include > 0)
								syslog(LOG_INFO, "|   |--[i] %s", dirp->d_name);
							free(cfgfilename);
							cfgfilename = NULL;
							break;
						}
					if (cfgfilename == NULL)
						continue; /* this file has been already included, include next file */
					if (check_cfgfilename() < 0)
						goto parsing_failed;
					if ( (fp = fopen(cfgfilename, "r")) == NULL) {
						Syslog(LOG_ERR, "fopen(%s, \"r\"): %m", cfgfilename);
						goto parsing_failed;
					}
					if (mode == TEST_PARSING)
						printf("#  |   |--[+] %s\n", dirp->d_name);
					else if (use_syslog && debug_include > 0)
						syslog(LOG_INFO, "|   |--[+] %s", dirp->d_name);
					++nincluded;
					if ( (ptr_inode = realloc(include_inode, (nincluded + 1) * sizeof *include_inode)) == NULL) {
						Syslog(LOG_ERR, "realloc: %m");
						goto parsing_failed;
					}
					include_inode = ptr_inode;
					include_inode[nincluded] = statbuf.st_ino;
					break;
				}
				if (cfgfilename != NULL)
					break;
			} else {
				/* "file" parameter */
				cfgfilename = incp->file;
				if (lstat(cfgfilename, &statbuf) < 0) {
					if (errno == ENOENT && incp->question) {
						if (mode == TEST_PARSING)
							printf("#  |--[n] %s\n", cfgfilename);
						else if (use_syslog && debug_include > 1)
							syslog(LOG_INFO, "|--[n] %s", cfgfilename);
						cfgfilename = NULL;
						continue; /* include next file or directory */
					}
					Syslog(LOG_ERR, "lstat(%s): %m", cfgfilename);
					goto parsing_failed;
				}
				if (check_cfgfilename() < 0)
					goto parsing_failed;
				for (k = 0; k < nincluded + 1; ++k)
					if (statbuf.st_ino == include_inode[k]) {
						if (mode == TEST_PARSING)
							printf("#  |--[i] %s\n", cfgfilename);
						else if (use_syslog && debug_include > 0)
							syslog(LOG_INFO, "|--[i] %s", cfgfilename);
						cfgfilename = NULL;
						break;
					}
				if (cfgfilename == NULL)
					continue; /* this file has been already included, include next file or directory */
				if ( (fp = fopen(cfgfilename, "r")) == NULL) {
					Syslog(LOG_ERR, "fopen(%s, \"r\"): %m", cfgfilename);
					goto parsing_failed;
				}
				if (mode == TEST_PARSING)
					printf("#  |--[+] %s\n", cfgfilename);
				else if (use_syslog && debug_include > 0)
					syslog(LOG_INFO, "|--[+] %s", cfgfilename);
				++nincluded;
				if ( (ptr_inode = realloc(include_inode, (nincluded + 1) * sizeof *include_inode)) == NULL) {
					Syslog(LOG_ERR, "realloc: %m");
					goto parsing_failed;
				}
				include_inode = ptr_inode;
				include_inode[nincluded] = statbuf.st_ino;
				break;
			}
		}
	}
parsing_failed:
	Syslog(LOG_ERR, "parsing failed!");
	if (fp != NULL && fclose(fp) != 0)
		Syslog(LOG_ERR, "fclose(%s): %m", cfgfilename);
	if (dp != NULL) {
		if (closedir(dp) < 0)
			Syslog(LOG_ERR, "closedir(%s): %m", (include + ninclude_curr)->dir);
		free(cfgfilename);
	}
	free(buf);
	free(db_dir);
	free(include_inode);
	free_include();
	free_worktime_global();
	return -1;
}

/*
 * Build some regular expressions (regex). It helps to write much more
 * simple code for all parse_*() functions.
 */
static int
build_config_regexes(void)
{
#define	pat_rule	"^rule[ \t]+[^ \t{}#;]+$"
#if defined(WITH_IPFW) || defined(WITH_IP6FW)
# define pat_ipfw_val	"^-?[[:digit:]]+(\\.[[:digit:]]+)?([ \t]+-?[[:digit:]]+(\\.[[:digit:]]+)?)*$"
#endif
#ifdef WITH_IPFIL
# define pat_ipfil_val	"^-?[io]([[:digit:]]+)?@[[:digit:]]+([ \t]+-?[io]([[:digit:]]+)?@[[:digit:]]+)*$"
#endif
#ifdef WITH_PF
# define pat_pf_val	"^-?[[:digit:]]+([ \t]+-?[[:digit:]]+)*$"
#endif
#define pat_time_val	"^([[:digit:]]+[smh][ \t]*)+$"
#define pat_emptyline	"^[ \t]*$"
#define	pat_size_val	"^([[:digit:]]+[bkmgtBKMGT][ \t]*)+$"
#define pat_limit	"^limit[ \t]+[^ \t{}#;]+$"
#define pat_exec	"^exec[ \t]*(\\(:[-_[:alnum:]]+\\)|\\([-_[:alnum:]]+(:([-_[:alnum:]]+)?)?\\))?$"
#define pat_time_exp_val "^(\
(\\+[mhdwDWM])?[ \t]*(([[:digit:]]+[smhdwDWM][ \t]*)+)?|\
(([[:digit:]]+[smhdwDWM][ \t]*)+)?[ \t]*(\\+[mhdwDWM])?)$"
#define pat_if_limit	"^(if_limit|if_limit_reached|if_limit_is_reached)$"
#define pat_if_nolimit	"^(if_nolimit|if_limit_not_reached|if_limit_is_not_reached)$"
#define pat_db_group_val "^[-_[:alnum:]]+$"
#define pat_worktime_val "\
^[smtwhfaSMTWHFA][ \t]*(\\*|[[:digit:]]{1,2}:[[:digit:]]{1,2}-[[:digit:]]{1,2}:[[:digit:]]{1,2}([ \t]+[[:digit:]]{1,2}:[[:digit:]]{1,2}-[[:digit:]]{1,2}:[[:digit:]]{1,2})*)\
([ \t]+[smtwhfaSMTWHFA][ \t]*(\\*|[[:digit:]]{1,2}:[[:digit:]]{1,2}-[[:digit:]]{1,2}:[[:digit:]]{1,2}([ \t]+[[:digit:]]{1,2}:[[:digit:]]{1,2}-[[:digit:]]{1,2}:[[:digit:]]{1,2})*))*$"
#define pat_yesno_val	"^([yY][eE][sS]|[nN][oO])$"
#define pat_file	"^file[ \t]*(\\([ \t]*\\?[ \t]*\\))?$"
#define pat_files	"^files[ \t]*(\\([ \t]*\\?[ \t]*\\))?[ \t]*\\(.*\\)$"
#ifdef WITH_MYSQL
#define pat_sql_port    "^[[:digit:]]{1,5}$"
#endif /* WITH_MYSQL */

	static int	already_built = 0;

#define	REGCOMP(x)								\
	if ( (re_errcode = regcomp(&reg_ ## x, pat_ ## x, REG_EXTENDED|REG_NOSUB)) != 0) {\
		re_form_errbuf();						\
		Syslog(LOG_ERR, "regcomp(" #x "): %s", re_errbuf);		\
		return -1;							\
	}

	if (already_built)
		return 0;
	REGCOMP(rule);
#if defined(WITH_IPFW) || defined(WITH_IP6FW)
	REGCOMP(ipfw_val);
#endif
#ifdef WITH_MYSQL
        REGCOMP(sql_port);
#endif /* WITH_MYSQL */
	REGCOMP(emptyline);
	REGCOMP(size_val);
	REGCOMP(time_val);
#ifdef WITH_IPFIL
	REGCOMP(ipfil_val);
#endif
#ifdef WITH_PF
	REGCOMP(pf_val);
#endif
	REGCOMP(limit);
	REGCOMP(exec);
	REGCOMP(time_exp_val);
	REGCOMP(if_limit);
	REGCOMP(if_nolimit);
	REGCOMP(db_group_val);
	REGCOMP(worktime_val);
	REGCOMP(yesno_val);
	REGCOMP(file);
	REGCOMP(files);
	already_built = 1;
	return 0;
}

/*
 * Following functions are used for viewing configuration file, size, time, etc.
 * in human-readable format.
 */

/*
 * Convert size to human readable string (Tbytes, Gbytes, etc.).
 */
char *
show_bytes(u_quad_t a)
{
	char		*ptr;
	u_quad_t	t, g, m, k, b;

	if (a == 0)
		return "0B";
	t = a / TBYTE;
	a -= t * TBYTE;
	g = a / GBYTE;
	a -= g * GBYTE;
	m = a / MBYTE;
	a -= m * MBYTE;
	k = a / KBYTE;
	b = a - k * KBYTE;
	free(show_bytes_buf);
	show_bytes_buf = NULL;
	if (asprintf(&show_bytes_buf, "%quT %quG %quM %quK %quB", t, g, m, k, b) < 0) {
		Syslog(LOG_ERR, "show_bytes: asprintf: %m");
		return "(error)";
	}
	ptr = show_bytes_buf;
	if (t == 0) {
		ptr = skip_first_space(ptr);
		if (g == 0) {
			ptr = skip_first_space(ptr);
			if (m == 0) {
				ptr = skip_first_space(ptr);
				if (k == 0)
					ptr = skip_first_space(ptr);
			}
		}
	}
	if (b == 0) {
		last_space_to_nul(ptr);
		if (k == 0) {
			last_space_to_nul(ptr);
			if (m == 0) {
				last_space_to_nul(ptr);
				if (g == 0)
					last_space_to_nul(ptr);
			}
		}
	}
	return ptr;
}

/*
 * show_bytes2() is wrapper for show_bytes() and should be called when
 * we want to call show_bytes() "two times" and keep both results.
 */
char *
show_bytes2(u_quad_t a)
{
	static char	*show_bytes_buf2 = NULL;

	char		*show_bytes_buf_save, *ptr;

	free(show_bytes_buf2);
	show_bytes_buf_save = show_bytes_buf;
	show_bytes_buf = NULL;
	ptr = show_bytes(a);
	show_bytes_buf2 = show_bytes_buf;
	show_bytes_buf = show_bytes_buf_save;
	return ptr;
}

/*
 * Convert time to human readable string (hours, minutes and seconds).
 */
char *
show_time(u_int a)
{
	static char	*show_time_buf = NULL;

	char		*ptr;
	u_int		h, m, s;

	if (a == 0)
		return "0s";
	h = a / HOUR;
	a -= h * HOUR;
	m = a / MINUTE;
	s = a - m * MINUTE;
	free(show_time_buf);
	show_time_buf = NULL;
	if (asprintf(&show_time_buf, "%uh %um %us", h, m, s) < 0) {
		Syslog(LOG_ERR, "show_time: asprintf: %m");
		return "(error)";
	}
	ptr = show_time_buf;
	if (h == 0) {
		ptr = skip_first_space(ptr);
		if (m == 0)
			ptr = skip_first_space(ptr);
	}
	if (s == 0) {
		last_space_to_nul(ptr);
		if (m == 0)
			last_space_to_nul(ptr);
	}
	return ptr;
}

/*
 * Convert expired time to human readable string.
 */
static void
show_time_exp(struct time_exp *time_exp)
{
	u_int	t, a = time_exp->seconds;

	if (time_exp->upto != UPTO_SIMPLE && time_exp->side == 0)
		printf(" +%c", time_exp->upto);
	if (time_exp->monthes != 0)
		printf(" %uM", time_exp->monthes);
	t = a / DAY;
	if (t != 0) {
		printf(" %uD", t);
		a -= t * DAY;
	}
	t = a / HOUR;
	if (t != 0) {
		printf(" %uh", t);
		a -= t * HOUR;
	}
	t = a / MINUTE;
	if (t != 0) {
		printf(" %um", t);
		a -= t * MINUTE;
	}
	if (a != 0)
		printf(" %us", a);
	if (time_exp->upto != UPTO_SIMPLE && time_exp->side == 1)
		printf(" +%c", time_exp->upto);
}

/*
 * Output "exec" parameter.
 */
static void
show_exec(struct cmd *cmdp)
{
	struct passwd	*passwdp;
	struct group	*groupp;

	printf("exec");
	if (cmdp->uid_set || cmdp->gid_set) {
		if (cmdp->uid_set) {
			if (cmdp->uid_named) {
				if ( (passwdp = getpwuid(cmdp->uid)) == NULL)
					printf("(%lu", cmdp->uid);
				else
					printf("(%s", passwdp->pw_name);
			} else
				printf("(%lu", cmdp->uid);
		} else
			printf("(");
		if (cmdp->gid_set) {
			if  (cmdp->gid_named) {
				if ( (groupp = getgrgid(cmdp->gid)) == NULL)
					printf(":%lu)", cmdp->gid);
				else
					printf(":%s)", groupp->gr_name);
			} else
				printf(":%lu)", cmdp->gid);
		} else if (cmdp->nsuppl_gid > 0)
			printf(")");
		else
			printf(":)");
	}
	printf(" = %s\n", cmdp->str);
}

/*
 * Output "startup" and "shutdown" sections with "exec" parameters.
 * Also output "if_limit_is_reached" and "if_limit_is_not_reached" sections
 * if they are present.
 */
static void
show_commands(struct commands *commandsp, const char *firstline, const char *prefix)
{
	struct cmd	*cmdp;
	u_int		k;
	
	if (commandsp->cmd || commandsp->cmd_if_limit || commandsp->cmd_if_nolimit) {
		printf("%s%s {\n", prefix, firstline);
		for (k = 0, cmdp = commandsp->cmd; k < commandsp->ncmd; ++cmdp, ++k) {
			printf("%s    ", prefix);
			show_exec(cmdp);
		}
		if (commandsp->cmd_if_limit != NULL) {
			printf("%s    if_limit_is_reached {\n", prefix);
			for (k = 0, cmdp = commandsp->cmd_if_limit; k < commandsp->ncmd_if_limit; ++cmdp, ++k) {
				printf("%s        ", prefix);
				show_exec(cmdp);
			}
			printf("%s    }\n", prefix);
		}
		if (commandsp->cmd_if_nolimit != NULL) {
			printf("%s    if_limit_is_not_reached {\n", prefix);
			for (k = 0, cmdp = commandsp->cmd_if_nolimit; k < commandsp->ncmd_if_nolimit; ++cmdp, ++k) {
				printf("%s        ", prefix);
				show_exec(cmdp);
			}
			printf("%s    }\n", prefix);
		}
		printf("%s}\n", prefix);
	}
}

/*
 * Output "worktime" parameter.
 */
static void
show_worktime(struct worktime *wtp, const char *prefix)
{
	u_int		wday, i;
	const char	wdays[] = "SMTWHFA";
	struct interval	*intp;

	printf("%sworktime =", prefix);
	for (wday = 1;;) {
		if (wtp[wday].interval != NULL) {
			printf(" %c", wdays[wday]);
			intp = wtp[wday].interval;
			if (wtp[wday].ninterval == 1 &&
			    intp->h1 == 0 && intp->m1 == 0 &&
			    intp->h2 == 24 && intp->m2 == 0)
				printf(" *");
			else
				for (i = 0; i < wtp[wday].ninterval; ++intp, ++i)
					printf(" %02hu:%02hu-%02hu:%02hu",
					    intp->h1, intp->m1,
					    intp->h2, intp->m2);
		}
		if (wday == 0)
			break;
		if (wday == 6)
			wday = 0;
		else
			++wday;
	}
	printf("\n");
}

static char *
boolean_str(int bool)
{
	return bool ? "yes" : "no";
}

/*
 * Output "db_group" parameter.
 */
static void
show_db_group(struct db_group *ptr)
{
	struct group	*groupp;

	if (ptr->group_set) {
		printf("    db_group = ");
		if (ptr->group_named) {
			if ( (groupp = getgrgid(ptr->group_id)) == NULL)
				printf("%lu\n", ptr->group_id);
			else
				printf("%s\n", groupp->gr_name);
		} else
			printf("%lu\n", ptr->group_id);
	}
}

static void
show_sign(short sign)
{
	if (sign == SUB)
		printf(" -");
	else
		printf(" ");
}


#if defined(WITH_IPFW) || defined(WITH_IP6FW)
static void
show_ipfwac(const char *param, struct ipfwac *ipfwacp, u_int nipfwac)
{
	u_int		i;
	struct ipfwac	*ptr;

	printf("    %s =", param);
	for (i = 0, ptr = ipfwacp; i < nipfwac; ++ptr, ++i) {
		show_sign(ptr->action);
		if (ptr->subnumber == 0)
			printf("%hu", ptr->number);
		else
			printf("%hu.%u", ptr->number, ptr->subnumber);
	}
	printf("\n");
}
#endif /* defined(WITH_IPFW) || defined(WITH_IP6FW) */

#ifdef WITH_IPFIL
static void
show_ipfilac(const struct ipfilac *ipfilacp, char type)
{
	u_int		i, j;
	struct ipfilac_group	*groupp;
	struct ipfilac_rule	*rulep;

	printf("    ipfil =");
	for (i = 0, groupp = ipfilacp->group; i < ipfilacp->ngroup; ++groupp, ++i)
		for (j = 0, rulep = groupp->rule; j < groupp->nrule; ++rulep, ++j) {
			show_sign(rulep->action);
			printf("%c", type);
			if (groupp->group_number > 0)
				printf("%u", groupp->group_number);
			printf("@%u", rulep->rule_number);
		}
	printf("\n");
}
#endif /* WITH_IPFIL */

/*
 * Main function for outputing indented configuration file.
 */
void
show_config(void)
{
	u_int		i;
	struct rule	*rule;
	struct limit	*limit;
#ifdef WITH_PF
	struct pfac	*pfacp;
#endif
	struct cmd	*cmdp;

	if (testconfig > 1 && include_section_set)
		printf("# \n#  %d file%s from %d \"include\" section%s w%s included.\n\
#  This output is not identical to the original content of\n\
#  the configuration file %s\n#\n\n", nincluded, nincluded > 1 ? "s" : "",
		    include_section_set, include_section_set > 1 ? "s" : "",
		    nincluded > 1 ? "ere" : "as", cfgfilename_main);
	if (global_section_set) {
		printf("global {\n");
		if (update_db_time_global != 0)
			printf("    update_db_time = %s\n", show_time(update_db_time_global));
		if (append_db_time_global != 0)
			printf("    append_db_time = %s\n", show_time(append_db_time_global));
		if (maxchunk_global != 0)
			printf("    maxchunk = %s\n", show_bytes(maxchunk_global));
		if (db_dir != NULL)
			printf("    db_dir = %s\n", db_dir);
		show_db_group(&db_group_global);
#ifdef WITH_MYSQL
		if (sql_name_set)
			printf("    sql_name = %s\n", sql_name);
		if (sql_user_set)
			printf("    sql_user = %s\n", sql_user);
		if (sql_pswd_set)
			printf("    sql_pswd = %s\n", sql_pswd);
		if (sql_host_set)
			printf("    sql_host = %s\n", sql_host);
		if (sql_port_set)
			printf("    sql_port = %d\n", sql_port);
#endif /* WITH_MYSQL */
		if (lock_db_set)
			printf("    lock_db = %s\n", boolean_str(lock_db));
		if (lock_wait_time != 0)
			printf("    lock_wait_time = %s\n", show_time(lock_wait_time));
		if (worktime_global_set)
			show_worktime(worktime_global, "    ");
		if (only_abs_paths_set)
			printf("    only_abs_paths = %s\n", boolean_str(only_abs_paths));
		printf("}\n\n");
	}
	if (debug_section_set) {
		printf("debug {\n");
#ifdef WITH_IPFW
		if (debug_ipfw_set)
			printf("    debug_ipfw = %d\n", debug_ipfw);
#endif
#ifdef WITH_IP6FW
		if (debug_ip6fw_set)
			printf("    debug_ip6fw = %d\n", debug_ip6fw);
#endif
#ifdef WITH_IPFIL
		if (debug_ipfil_set)
			printf("    debug_ipfil = %d\n", debug_ipfil);
#endif
#ifdef WITH_PF
		if (debug_pf_set)
			printf("    debug_pf = %d\n", debug_pf);
#endif
		if (debug_exec_set)
			printf("    debug_exec = %d\n", debug_exec);
		if (debug_limit_set)
			printf("    debug_limit = %d\n", debug_limit);
		if (debug_time_set)
			printf("    debug_time = %d\n", debug_time);
		if (debug_worktime_set)
			printf("    debug_worktime = %d\n", debug_worktime);
		if (debug_lock_set)
			printf("    debug_lock = %d\n", debug_lock);
		if (debug_include_set)
			printf("    debug_include = %d\n", debug_include);
		printf("}\n\n");
	}
	if (include_section_set) {
		struct include	*incp;

		printf("include {\n");
		for (i = 0, incp = include; i < ninclude; ++i, ++incp) {
			if (incp->use_re)
				printf("    files%s(%s) = %s\n",
				    incp->question ? "(?)" : "", incp->dir, incp->file);
			else
				printf("    file%s = %s\n",
				    incp->question ? "(?)" : "", incp->file);
		}
		printf("}\n\n");
	}
	if (startup_global.cmd != NULL) {
		show_commands(&startup_global, "startup", "");
		printf("\n");
	}
	if (shutdown_global.cmd != NULL) {
		show_commands(&shutdown_global, "shutdown", "");
		printf("\n");
	}
	SLIST_FOREACH(rule, &rule_head, rule_entry) {
		printf("rule %s {\n", rule->rulename);
		if (rule->info != NULL)
			printf("    info = %s\n", rule->info);
		show_db_group(&rule->db_group);
		if (rule->update_db_time != 0)
			printf("    update_db_time = %s\n", show_time(rule->update_db_time));
		if (rule->append_db_time != 0)
			printf("    append_db_time = %s\n", show_time(rule->append_db_time));
#ifdef WITH_IPFW
		if (rule->ipfwac != NULL)
			show_ipfwac("ipfw", rule->ipfwac, rule->nipfwac);
#endif
#ifdef WITH_IP6FW
		if (rule->ip6fwac != NULL)
			show_ipfwac("ip6fw", rule->ip6fwac, rule->nip6fwac);
#endif
#ifdef WITH_IPFIL
		if (rule->ipfilac_in.group != NULL)
			show_ipfilac(&rule->ipfilac_in, 'i');
		if (rule->ipfilac_out.group != NULL)
			show_ipfilac(&rule->ipfilac_out, 'o');
#endif
#ifdef WITH_PF
		if (rule->pfac != NULL) {
			printf("    pf =");
			for (i = 0, pfacp = rule->pfac; i < rule->npfac; ++pfacp, ++i) {
				show_sign(pfacp->action);
				printf("%u", pfacp->number);
			}
			printf("\n");
		}
#endif /* WITH_PF */

		if (rule->maxchunk != 0)
			printf("    maxchunk = %s\n", show_bytes(rule->maxchunk));
		if (rule->use_rule_worktime)
			show_worktime(rule->worktime, "    ");
		show_commands(&rule->rc[0], "startup", "    ");
		show_commands(&rule->rc[1], "shutdown", "    ");
		SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
			printf("    limit %s {\n", limit->limitname);
			if (limit->info != NULL)
				printf("        info = %s\n", limit->info);
			printf("        byte_limit = %s\n", show_bytes(limit->byte_limit));
			if (limit->zero_time_param.upto != UPTO_NOTSET) {
				printf("        zero_time =");
				show_time_exp(&limit->zero_time_param);
				printf("\n");
			}
			if (limit->reach.cmd != NULL) {
				printf("        reach {\n");
				for (i = 0, cmdp = limit->reach.cmd; i < limit->reach.ncmd; ++cmdp, ++i) {
					printf("            ");
					show_exec(cmdp);
				}
				printf("        }\n");
			}
			if (limit->use_worktime)
				show_worktime(limit->worktime, "        ");
			if (limit->expire.time.upto != UPTO_NOTSET) {
				printf("        expire {\n            expire_time =");
				show_time_exp(&limit->expire.time);
				printf("\n");
				for (i = 0, cmdp = limit->expire.cmd; i < limit->expire.ncmd; ++cmdp, ++i) {
					printf("            ");
					show_exec(cmdp);
				}
				printf("        }\n");
			}
			show_commands(&limit->rc[0], "startup", "        ");
			show_commands(&limit->rc[1], "shutdown", "        ");
			printf("    }\n");
		}
		printf("}\n\n");
	}
}
