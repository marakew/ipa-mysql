/*-
 * Copyright (c) 2000-2003 Andrey Simonenko
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
  "@(#)$Id: ipastat.c,v 1.6.2.4 2003/11/11 10:23:42 simon Exp $";
#endif /* !lint */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include <regex.h>

#include "ipastat.h"

#include "common.h"
#include "path.h"


static char	*rule = NULL;		/* -r <rule> */
static regex_t	rule_re;		/* compiled RE if -x -r <rule> */
static char	*limit = NULL;		/* -l <limit> */
static char	*time_interval = NULL;	/* -i|I <time-interval> */
static char	*time_back = NULL;	/* -p <time-back> */

static struct rules_opt {
	char	*rule;		/* -R <rule> */
	regex_t	rule_re;	/* compiled RE if -x -R <rule> */
}		*rules_opt = NULL;	/* -R <rule1> -R <rule2> ... */
static u_int	nrules_opt = 0;		/* #rules_opt */

static char	**rules = NULL;		/* list of rules */
static u_int	nrules = 0;		/* #rules */

static int	sort_by_cntr_flag = 0;	/* ==1 if -b, ==2 if -bb */
static char	*db_dir = DBDIR;	/* -d <db-directory>, database directory */
static int	quiet_info_flag = 0;	/* -q, suppress reading info files  */
static int	ac_per_day_flag = 1;	/* -t, output accounting per day or per timestamp */
static int	use_second_timestamp_flag = 0; /* ==1 if -I switch is set */
static int	check_dates_flag = 1;	/* ==0 if -e switch is set */
static int	print_table_flag = 1;	/* ==0 if -n switch is set */
static int	lock_db_flag = 0;	/* ==1 if -L switch is set */

static int	match_regex_flag = 0;	/* -x */

static uid_t	my_uid;			/* my UID */

static struct tm	curr_tm;	/* current local time */

static char	*lock_db_file;		/* "lock db" file absolute path name */
static int	lock_db_fd;		/* "lock db" FD */
static jmp_buf	env_alrm;

static const u_quad_t	uquad_max_ULL = UQUAD_MAX;

#define LOCK_WAIT_TIME	10	/* max #seconds wait for lock */

/* 2^10 base */
#define KBYTE	(1024ULL)
#define MBYTE	(1024ULL * KBYTE)
#define GBYTE	(1024ULL * MBYTE)
#define TBYTE	(1024ULL * GBYTE)

/*
 * How to get ROUND_KBYTE_ADD value (and don't use floating-point numbers):
 *
 *	0.(4)5 =~ 1
 *	x / 1024 = 0.(4)5
 *	x = 1024 * 0.(4)5
 *	x + y = 1024
 *	y = 1024 - x = 1024 - 1024 * 0.(4)5 = 1024 * 0.(5) = 568.(8)
 *	ROUND_KBYTE_ADD = [568.(8)] = 568
 *
 * Result:
 *
 *	r = (x + 568) / 1024
 */
#define ROUND_KBYTE_ADD	(568ULL)
#define ROUND_MBYTE_ADD	(582542ULL)
#define ROUND_GBYTE_ADD	(596523235ULL)
#define ROUND_TBYTE_ADD	(610839793207ULL)

/* 10^3 base */
#define KBYTE10	1000ULL
#define MBYTE10	(1000ULL * KBYTE10)
#define GBYTE10	(1000ULL * MBYTE10)
#define TBYTE10	(1000ULL * GBYTE10)

#define ROUND_KBYTE10_ADD	(555ULL)
#define ROUND_MBYTE10_ADD	(555555ULL)	
#define ROUND_GBYTE10_ADD	(555555555ULL)
#define ROUND_TBYTE10_ADD	(555555555555ULL)

static u_quad_t	kbyte = KBYTE,
		mbyte = MBYTE,
		gbyte = GBYTE,
		tbyte = TBYTE;

static struct {
	u_quad_t	div;
	u_quad_t	add;
} bcnt_conv_coef[2][4] = {
	{
		{ KBYTE, ROUND_KBYTE_ADD },
		{ MBYTE, ROUND_MBYTE_ADD },
		{ GBYTE, ROUND_GBYTE_ADD },
		{ TBYTE, ROUND_TBYTE_ADD }
	},
	{
		{ KBYTE10, ROUND_KBYTE10_ADD },
		{ MBYTE10, ROUND_MBYTE10_ADD },
		{ GBYTE10, ROUND_GBYTE10_ADD },
		{ TBYTE10, ROUND_TBYTE10_ADD }
	}
};

static u_quad_t bcnt_conv_div;
static u_quad_t bcnt_conv_add;

typedef enum {
	Kbyte = 0,
	Mbyte,
	Gbyte,
	Tbyte,
	Complete
} bcnt_conv_type;

static bcnt_conv_type bcnt_conv_flag = Mbyte;
static const char *bcnt_conv_msg[] = { "Kbytes", "Mbytes", "Gbytes", "Tbytes", "*bytes" };

static char * (*conv_bcnt)(const u_quad_t *);

#define TINT_LEFT_PART	0
#define TINT_RIGHT_PART	1

static char	*partname[] = {"left", "right"}; /* name of time-interval part */

typedef enum {
	TINT_YYYY,	/* YYYY.* */
	TINT_MM,	/* MM.* */
	TINT_DD,	/* DD.* */
	TINT_OTHER	/* /hh:*, /mm:* /ss:* */
} TINT_TYPE;
static TINT_TYPE	tint_most_spec_value;

#ifdef __GNUC__
static void	err_exit(const char *, ...) __attribute__ ((noreturn, format (printf, 1, 2)));
static void	errx_exit(const char *, ...) __attribute__ ((noreturn, format (printf, 1, 2)));
static void	warn_exit(const char *, ...) __attribute__ ((noreturn, format (printf, 1, 2)));
static void	format_err(const char *, ...) __attribute__ ((format (printf, 1, 2)));
#else
static void	err_exit(const char *, ...);
static void	errx_exit(const char *, ...);
static void	warn_exit(const char *, ...);
static void	format_err(const char *, ...);
#endif

static void	show_usage(char *), show_version(void);
static int	readline(char **, size_t *, FILE *, const char *);
static char	*get_info(const char *, const char *);
static void	lock_whole_db_read(void);
static void	unlock_whole_db(void);
static void	set_sighandlers(void);
static void	lock_db_file_until_end(const char *, int, int, short);
static void	prepare_match_regex(void);

/*
 * Regular expressions for checking time interval given in the -i, -I
 * and -p option.
 */
#define pat_time_interval_pre "^[^-]+(-[^-]+)?$"
#define pat_time_interval "\
^\
(\
[[:digit:]]{4,}(\\.([[:digit:]]{1,2}|[[:alpha:]]{3}))?(\\.[[:digit:]]{1,2})?|\
([[:digit:]]{1,2}|[[:alpha:]]{3})?(\\.[[:digit:]]{1,2})?\
)?\
(\
/[[:digit:]]{1,2}(:[[:digit:]]{1,2})?(:[[:digit:]]{1,2})?\
)?\
$"
#define pat_time_back	"^[[:digit:]]+[dmwyDMWY]$"

#define	REGCOMP(x)						\
	if ( (re_errcode = regcomp(&reg_ ## x, pat_ ## x, REG_EXTENDED|REG_NOSUB)) != 0) {\
		re_form_errbuf();				\
		errx_exit("regcomp(" #x "): %s", re_errbuf);	\
	}
#define REGFREE(x)	regfree(&reg_ ## x)



/* struct for list of rules or limits */
struct name_list {
	char	*name;
	char	*info;
};

struct summary_ac_list {
	char		*rule;
	char		*info;
	char		*bytes_str;
	char		*bytes_conv_str;
	u_quad_t	bytes;
	u_int		uquad_max_cnt;
};

static const char use_e_switch_msg[] = "(use the -e switch to ignore such errors).";
static const char you_not_allowed_msg[] = "you are not allowed to access rule \"%s\".";

/*
 * Check if the user can access a rule.
 */
static int
can_access_rule(const char *rulename)
{
	int		result;
	char		*path;
	struct stat	statbuf;

	if (strcmp(rulename, ".") == 0 || strcmp(rulename, "..") == 0 ||
	    strcmp(rulename, LOCKDBFILE) == 0)
		warn_exit("rule name \"%s\" is not permited.", rulename);
	if (asprintf(&path, "%s/%s", db_dir, rulename) < 0)
		err_exit("asprintf");
	if (lstat(path, &statbuf) < 0) {
		if (errno == ENOENT)
			warn_exit("rule \"%s\" does not exist.", rulename);
		err_exit("lstat(%s)", path);
	}
	if (!S_ISDIR(statbuf.st_mode))
		errx_exit("%s is expected to be a directory.", path);
	if (my_uid == 0) {
		free(path);
		return 1;
	}
	if (access(path, R_OK) == 0)
		result = 1;
	else {
		if (errno != EACCES)
			err_exit("access(%s)", path);
		result = 0;
	}
	free(path);
	return result;
}

/*
 * Find a rule in the db_dir which matches rule_re regular expression and
 * which is allowed for access by the user.
 */
static void
get_rule_by_regex(void)
{
	int		nrules_flag = 0, match_flag = 0;
	DIR		*dp;
	struct dirent	*dirp;

	if ( (dp = opendir(db_dir)) == NULL)
		err_exit("opendir(%s)", db_dir);
	while ( (dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0 ||
		    strcmp(dirp->d_name, LOCKDBFILE) == 0)
			continue;
		nrules_flag = 1;
		if (regexec(&rule_re, dirp->d_name, 0, (regmatch_t *)NULL, 0) == 0) {
			match_flag = 1;
			if (can_access_rule(dirp->d_name)) {
				regfree(&rule_re);
				if ( (rule = strdup(dirp->d_name)) == NULL)
					err_exit("get_rule_by_regex: strdup");
				if (closedir(dp) < 0)
					err_exit("closedir(%s)", db_dir);
				return;
			}
		}
	}
	if (nrules_flag == 0)
		warn_exit("no rules were found.");
	else {
		if (match_flag == 0)
			warn_exit("there is not any rule which matches given regular expression.");
		else
			warn_exit("you are not allowed to browse any rule, which matches given regular expression or such rules were not found.");
	}
}

/*
 * Find rules in the db_dir which match rules[].rule_re regular expressions
 * and which are allowed for access by the user.
 */
static void
get_rules_by_regexs(void)
{
	int		nrules_flag = 0, match_flag = 0;
	u_int		i;
	DIR		*dp;
	struct dirent	*dirp;

	if ( (dp = opendir(db_dir)) == NULL)
		err_exit("opendir(%s)", db_dir);
	while ( (dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0 ||
		    strcmp(dirp->d_name, LOCKDBFILE) == 0)
			continue;
		nrules_flag = 1;
		for (i = 0; i < nrules_opt; ++i)
			if (regexec(&rules_opt[i].rule_re, dirp->d_name, 0, (regmatch_t *)NULL, 0) == 0) {
				match_flag = 1;
				if (can_access_rule(dirp->d_name)) {
					if ( (rules = realloc(rules, (nrules + 1) * sizeof * rules)) == NULL)
						err_exit("realloc");
					if ( (rules[nrules] = strdup(dirp->d_name)) == NULL)
						err_exit("strdup");
					++nrules;
					break;
				}
			}
	}
	if (nrules_flag == 0)
		warn_exit("no rules were found.");
	if (rules == NULL) {
		if (match_flag == 0)
			warn_exit("there is not any rule, which matches given regular expression(s).");
		else
			warn_exit("you are not allowed to access any rule, which matches given regular expression(s).");
	}
}

/*
 * Output error message about errors in time interval specified
 * in the -i or -I option.
 */
static void
time_interval_err(const char *message, int part)
{
	format_err("time interval (%s part): incorrect %s", partname[part], message);
}

/*
 * Return max day number in given month,
 * ptr->tm_mon is equal to human month number.
 */
static int
max_day(const struct tm *ptr)
{
	switch (ptr->tm_mon) {
	case 4:
	case 6:
	case 9:
	case 11:
		return 30;
	case 2: /* February */
		return ptr->tm_year % 4 == 0 ? 29 : 28;
	default:
		return 31;
	}
	/* NOTREACHED */
}

/*
 * Parse left or right part of time interval specified in the -i or -I option.
 * Format of time interval is described in ipastat(8).
 * Complete left or right part if it is needed.
 */
static void
parse_time_interval(char *s, struct tm *tm_ptr, int part)
{
	int		n, val1, val2, val3;
	char		*ptr;
	const char	mon_name[][3] = {
		"jan", "feb", "mar", "apr", "may", "jun",
		"jul", "aug", "sep", "oct", "nov", "dec"
	};

	tint_most_spec_value = TINT_OTHER;

	/* initial value for time in the left part,
	   for the right part these fields are completed below */
	tm_ptr->tm_hour = tm_ptr->tm_min = tm_ptr->tm_sec = 0;

	if (*s != '/') {
		/* date is specified */
		if (*s == '.') {
			/* .DD */
			tint_most_spec_value = TINT_DD;
			errno = 0;
			if (sscanf(++s, "%d", &tm_ptr->tm_mday) != 1)
				err_exit("sscanf(\"%s\", %%d): failed", s);
		} else {
			for (ptr = s; *ptr != '\0'; ++ptr) {
				if (isalpha(*ptr)) {
					for (n = 0; n < 12; ++n) {
						if (strncasecmp(ptr, mon_name[n], 3) == 0) {
							if (sprintf(ptr, "%02d", n + 1) != 2)
								err_exit("sprintf: failed");
							ptr += 2;
							do {
								*ptr = *(ptr + 1);
							} while (*++ptr != '\0');
							break;
						}
					}
					if (n == 12)
						time_interval_err("month name", part);
					break;
				}
			}
			errno = 0;
			if ( (n = sscanf(s, "%d.%d.%d", &val1, &val2, &val3)) < 1)
				err_exit("sscanf(\"%s\", %%d.%%d.%%d): failed", s);
			if ( (ptr = strchr(s, '.')) == NULL)
				if ( (ptr = strchr(s, '/')) == NULL)
					ptr = strchr(s, '\0');
			switch (n) {
			case 3: /* YYYY.MM.DD */
				tint_most_spec_value = TINT_YYYY;
				tm_ptr->tm_year = val1;
				tm_ptr->tm_mon = val2;
				tm_ptr->tm_mday = val3;
				break;
			case 2:
				if (ptr - s >= 4) {
					/* YYYY.MM */
					tint_most_spec_value = TINT_YYYY;
					tm_ptr->tm_year = val1;
					tm_ptr->tm_mon = val2;
					tm_ptr->tm_mday = part == TINT_LEFT_PART ? 1 : max_day(tm_ptr);
				} else {
					/* MM.DD */
					tint_most_spec_value = TINT_MM;
					tm_ptr->tm_mon = val1;
					tm_ptr->tm_mday = val2;
				}
				break;
			default: /* 1 */
				if (ptr - s >= 4) {
					/* YYYY */
					tint_most_spec_value = TINT_YYYY;
					tm_ptr->tm_year = val1;
					if (part == TINT_LEFT_PART)
						tm_ptr->tm_mon = tm_ptr->tm_mday = 1;
					else {
						tm_ptr->tm_mon = 12;
						tm_ptr->tm_mday = max_day(tm_ptr);
					}
				} else {
					/* MM */
					tint_most_spec_value = TINT_MM;
					tm_ptr->tm_mon = val1;
					tm_ptr->tm_mday = part == TINT_LEFT_PART ? 1 : max_day(tm_ptr);
				}
			}
		}
	}

	n = 0;
	if ( (s = strchr(s, '/')) != NULL) {
		/* time is specified */
		errno = 0;
		if ( (n = sscanf(++s, "%d:%d:%d", &val1, &val2, &val3)) < 1)
			err_exit("sscanf(\"%s\", %%d:%%d:%%d): failed", s);
		if (n >= 1)
			tm_ptr->tm_hour = val1;	/* hh */
		if (n >= 2)
			tm_ptr->tm_min = val2;  /* hh:mm */
		if (n == 3)
			tm_ptr->tm_sec = val3;  /* hh:mm:ss */
	}

	if (tm_ptr->tm_mon == 0 || tm_ptr->tm_mon > 12)
		time_interval_err("month", part);
	if (tm_ptr->tm_mday == 0 || tm_ptr->tm_mday > 31)
		time_interval_err("day", part);
	if (tm_ptr->tm_hour > 23)
		time_interval_err("hours", part);
	if (tm_ptr->tm_min > 59)
		time_interval_err("minutes", part);
	if (tm_ptr->tm_sec > 59)
		time_interval_err("seconds", part);

	if (part == TINT_RIGHT_PART) /* complete value of time for right part if it is needed */
		switch (n) {
		case 2:	/* hh:mm */
			if (++tm_ptr->tm_min > 59)
				tm_ptr->tm_min = 0;
			else
				break;
			/* FALLTHROUGH */
		case 1:	/* hh */
			if (++tm_ptr->tm_hour <= 23)
				break;
			/* FALLTHROUGH */
		case 0:
			tm_ptr->tm_hour = 24;
		}
}

/*
 * Create buffer and save human readable date and time in it.
 */
static char *
tm_str(const struct tm *tm_ptr)
{
	char	*buf;

	if (asprintf(&buf, "%d.%02d.%02d/%02d:%02d:%02d",
	    tm_ptr->tm_year, tm_ptr->tm_mon, tm_ptr->tm_mday,
	    tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec) < 0)
		err_exit("asprintf");
	return buf;
}

/*
 * Convert byte counter to {K|M|G|T}bytes and save it in
 * allocared buffer.
 */
static char *
conv_bcnt_round(const u_quad_t *bcntp)
{
	char		*buf;
	u_quad_t	r;

	if (*bcntp <= UQUAD_MAX - bcnt_conv_add)
		r = (*bcntp + bcnt_conv_add) / bcnt_conv_div;
	else
		r = UQUAD_MAX / bcnt_conv_div;
	if (asprintf(&buf, "%qu", r) < 0)
		err_exit("asprintf");
	return buf;
}

/*
 * Convert given value of bytes as much as possible.
 */
static char *
conv_bcnt_completely(const u_quad_t *bcntp)
{
	char		*buf;
	u_quad_t	a = *bcntp;
	u_quad_t	t, g, m, k, b;

	if (a == 0)
		return "0B";
	t = a / tbyte;
	a -= t * tbyte;
	g = a / gbyte;
	a -= g * gbyte;
	m = a / mbyte;
	a -= m * mbyte;
	k = a / kbyte;
	b = a - k * kbyte;
	if (asprintf(&buf, "%quT %quG %quM %quK %quB", t, g, m, k, b) < 0)
		err_exit("asprintf");
	if (t == 0) {
		buf = skip_first_space(buf);
		if (g == 0) {
			buf = skip_first_space(buf);
			if (m == 0) {
				buf = skip_first_space(buf);
				if (k == 0)
					buf = skip_first_space(buf);
			}
		}
	}
	if (b == 0) {
		last_space_to_nul(buf);
		if (k == 0) {
			last_space_to_nul(buf);
			if (m == 0) {
				last_space_to_nul(buf);
				if (g == 0)
					last_space_to_nul(buf);
			}
		}
	}
	return buf;
}

/*
 * Output one line of the table.
 * n - #arguments,
 * ... - each argument is an unsigned integer equal to the width of a column.
 */
static void
print_table_line(u_int n, ...)
{
	va_list	ap;
	u_int	width, i;

	if (!print_table_flag)
		return;
	va_start(ap, n);
	while (n--) {
		printf("+");
		width = va_arg(ap, u_int);
		for (i = 0; i < width + 2; ++i)
			printf("-");
	}
	va_end(ap);
	printf("+\n");
}

/*
 * Get values of the time interval.
 * Option: [-p <time-back>] -i|I <time-interval>
 */
static void
get_time_interval(struct tm *tm1, struct tm *tm2)
{
	int	back_years = 0, back_months = 0,
		back_days = 0, back_weeks = 0;
	time_t	curr_time;

	time(&curr_time);
	localtime_r(&curr_time, &curr_tm);
	++curr_tm.tm_mon;
	curr_tm.tm_year += 1900;

	if (time_back != NULL) {
		/* -p option */
		int	value;
		char	errmsg[] = "time-back: too big value of %s in the -p option.";
		regex_t	reg_time_back;

		REGCOMP(time_back);
		if (REGEXEC(time_back, time_back) != 0)
			format_err("time-back");
		REGFREE(time_back);
		errno = 0;
		if (sscanf(time_back, "%d", &value) != 1)
			err_exit("sscanf(\"%s\", %%d): failed", time_back);
		switch (time_back[strlen(time_back) - 1]) {
		case 'm':
		case 'M':
			back_months = value;
			if (12 * curr_tm.tm_year + curr_tm.tm_mon <= back_months)
				format_err(errmsg, "months");
			break;
		case 'w':
		case 'W':
			back_weeks = value;
			if (12 * curr_tm.tm_year <= back_weeks % 4) /* simplified checking */
				format_err(errmsg, "weeks");
			break;
		case 'd':
		case 'D':
			back_days = value;
			if (curr_tm.tm_year <= back_days % 365)  /* simplified checking */
				format_err(errmsg, "days");
			break;
		default: /* 'y' or 'Y' */
			back_years = value;
			if (curr_tm.tm_year < back_years)
				format_err(errmsg, "years");
		}
		if (value == 0) 
			errx_exit("incorrect value in the \"-p %s\" option.", time_back);
		memcpy(tm1, &curr_tm, sizeof *tm1);
		memcpy(tm2, tm1, sizeof *tm2);
		tm1->tm_hour = tm1->tm_min = tm1->tm_sec = tm2->tm_min = tm2->tm_sec = 0;
		tm2->tm_hour = 24;
		tm1->tm_mday = 1;
		if (back_months > 0) {
			if (back_months >= tm1->tm_mon) {
				back_months -= tm1->tm_mon;
				tm1->tm_year = tm2->tm_year -= 1 + back_months / 12;
				tm1->tm_mon = tm2->tm_mon = 12 - back_months % 12;
			} else
				tm1->tm_mon = tm2->tm_mon -= back_months;
			tm2->tm_mday = max_day(tm2);
		} else if (back_weeks > 0) {
			if (curr_tm.tm_wday == 0) /* Sunday? */
				curr_time -= (6 + back_weeks * 7) * 24 * 60 * 60;
			else
				curr_time -= (curr_tm.tm_wday + back_weeks * 7) * 24 * 60 * 60;
			localtime_r(&curr_time, &curr_tm);
			tm1->tm_year = curr_tm.tm_year + 1900;
			tm1->tm_mon = curr_tm.tm_mon + 1;
			tm1->tm_mday = curr_tm.tm_mday;
			curr_time += 6 * 24 * 60 * 60;
			localtime_r(&curr_time, &curr_tm);
			tm2->tm_year = curr_tm.tm_year + 1900;
			tm2->tm_mon = curr_tm.tm_mon + 1;
			tm2->tm_mday = curr_tm.tm_mday;
		} else if (back_years > 0) {
			tm1->tm_year = tm2->tm_year -= back_years;
			tm1->tm_mon = 1;
			tm2->tm_mon = 12;
			tm2->tm_mday = max_day(tm2);
		} else /* back_days > 0 */ {
			if (back_days >= curr_tm.tm_mday) {
				curr_time -= back_days * 24 * 60 * 60;
				localtime_r(&curr_time, &curr_tm);
				tm1->tm_year = tm2->tm_year = curr_tm.tm_year + 1900;
				tm1->tm_mon = tm2->tm_mon = curr_tm.tm_mon + 1;
				tm1->tm_mday = tm2->tm_mday = curr_tm.tm_mday;
			} else
				tm1->tm_mday = tm2->tm_mday = curr_tm.tm_mday - back_days;
		}
	}
	if (time_interval == NULL && time_back == NULL) {
		/* no -i and -p options, current month */
		memcpy(tm1, &curr_tm, sizeof *tm1);
		memcpy(tm2, tm1, sizeof *tm2);
		tm1->tm_hour = tm1->tm_min = tm1->tm_sec = tm2->tm_min = tm2->tm_sec = 0;
		tm2->tm_hour = 24;
		tm1->tm_mday = 1;
		tm2->tm_mday = max_day(tm2);
	}
	if (time_interval != NULL) {
		/* -i option */
		char	*split_ptr;
		regex_t	reg_time_interval_pre, reg_time_interval;

		REGCOMP(time_interval);
		REGCOMP(time_interval_pre);
		if (REGEXEC(time_interval_pre, time_interval) != 0)
			format_err("time-interval (wrong parts).");
		REGFREE(time_interval_pre);
		if ( (split_ptr = strchr(time_interval, '-')) != NULL) {
			*split_ptr = '\0';
			if (REGEXEC(time_interval, time_interval) != 0)
				format_err("time-interval (wrong left part).");
			++split_ptr;
			if (REGEXEC(time_interval, split_ptr) != 0)
				format_err("time-interval (wrong right part).");
		} else {
			if (REGEXEC(time_interval, time_interval) != 0)
				format_err("time-interval.");
			split_ptr = time_interval;
		}
		REGFREE(time_interval);
		if (time_back == NULL) {
			/* no -p option */
			memcpy(tm1, &curr_tm, sizeof *tm1);
			memcpy(tm2, tm1, sizeof *tm2);
			parse_time_interval(time_interval, tm1, TINT_LEFT_PART);
			parse_time_interval(split_ptr, tm2, TINT_RIGHT_PART);
		} else {
			/* -p option */
			char	errmsg[] = "incorrect time-interval (%s part): the most specified value in the time-interval should be \"%s\" with the given \"-p %s\" option.";
			int	i, tmp;

			if (back_weeks > 0)
				errx_exit("time-interval cannot be used with the \"-p %s\" option.", time_back);
			parse_time_interval(split_ptr, tm2, TINT_RIGHT_PART);
			tmp = tint_most_spec_value;
			parse_time_interval(time_interval, tm1, TINT_LEFT_PART);
			for (i = 0; i < 2; ++i) {
				if (back_years > 0) {
					if (tint_most_spec_value != TINT_MM)
						errx_exit(errmsg, partname[i], "month", time_back);
				} else if (back_months > 0) {
					if (tint_most_spec_value != TINT_DD)
						errx_exit(errmsg, partname[i], "day", time_back);
				} else /* back_days > 0 */ {
					if (tint_most_spec_value != TINT_OTHER)
						errx_exit(errmsg, partname[i], "hours", time_back);
				}
				tint_most_spec_value = tmp;
			}
		}
	}
	if (tmcmp(tm1, tm2) > 0)
		format_err("time-interval (date in the right part should be greater than date in the left part).");
}

/*
 * Output accounting information for rule.
 * Option: [-x] -r <rule>
 */
static void
print_rule_ac(void)
{
	char		oneline[DBRECORDSIZE + 1];
	char		*info, *path;
	int		year, ret, prev_mday;
	u_int		u_quad_max_summary_cnt = 0, uquad_max_cnt_per_day = 0,
			nrecords = 0, ndays = 0, i;
	char		*u_quad_max_str, *u_quad_max_conv_str = NULL; /* initial value isn't used */
	regex_t		reg_db_entry;
	u_quad_t	db_value, summary = 0, summary_per_day = 0;
	char		*summary_str, *summary_conv_str;
	FILE		*fp;
	char		*tm1_ptr, *tm2_ptr;
	u_int		width_1_1, width_1_2, width_1_3, width_1_4,
			width_2_1, width_2_2, width_2_3, width_2_4 = 0, width_2_5 = 0,
			tmp;
	struct tm	tm1, tm2, db_tm1, db_tm2;
	struct stat	statbuf;
	struct ac_list {
		char	*bytes;
		char	*bytes_conv;
		char	*date;
		u_int	uquad_max_cnt;
		u_short	h1, m1, s1, h2, m2, s2;
	} * ac_list = NULL;
	u_int		nac_list = 0;
	char		*format;
	u_int		lineno;

	get_time_interval(&tm1, &tm2);

	REGCOMP(db_entry);

	lock_whole_db_read();

	if (match_regex_flag) /* -x */
		get_rule_by_regex();
	else if (can_access_rule(rule) == 0)
		warn_exit(you_not_allowed_msg, rule);

	info = get_info(rule, (char *)NULL);

	width_1_1 = 4; /* Rule */
	width_1_2 = 4; /* Info */
	width_1_3 = 4; /* From */
	width_1_4 = 2; /* To */

	if ( (tmp = strlen(rule)) > width_1_1)
		width_1_1 = tmp;
	if (info != NULL)
		if ( (tmp = strlen(info)) > width_1_2)
			width_1_2 = tmp;
	tm1_ptr = tm_str(&tm1);
	tm2_ptr = tm_str(&tm2);
	if ( (tmp = strlen(tm1_ptr)) > width_1_3)
		width_1_3 = tmp;
	if ( (tmp = strlen(tm2_ptr)) > width_1_4)
		width_1_4 = tmp;

	width_2_1 = 4;	/* Date */
	if (ac_per_day_flag) {
		width_2_2 = 5; /* Bytes */
		width_2_3 = strlen(bcnt_conv_msg[bcnt_conv_flag]);
	} else {
		width_2_2 = 8; /* hh:mm:ss */
		width_2_3 = 8; /* hh:mm:ss */
		width_2_4 = 5; /* Bytes */
		width_2_5 = strlen(bcnt_conv_msg[bcnt_conv_flag]);
	}
	oneline[DBRECORDSIZE] = '\0';
	for (year = tm1.tm_year; year <= tm2.tm_year; ++year) {
		int	mon, mon1, mon2;

		mon1 = year == tm1.tm_year ? tm1.tm_mon : 1;
		mon2 = year == tm2.tm_year ? tm2.tm_mon : 12;
		for (mon = mon1; mon <= mon2; ++mon) {
			if (asprintf(&path, "%s/%s/%d/%02d", db_dir, rule, year, mon) < 0)
				err_exit("asprintf");
			if (lstat(path, &statbuf) < 0) {
				if (errno != ENOENT)
					err_exit("lstat(%s)", path);
				free(path);
				continue;
			}

			if (!S_ISREG(statbuf.st_mode))
				errx_exit("%s should be a regular file", path);

			if (statbuf.st_size == 0) {
				/* file is empty */
				free(path);
				continue;
			}

			if ( (fp = fopen(path, "r")) == NULL)
				err_exit("fopen(%s, \"r\")", path);

			db_tm1.tm_year = db_tm2.tm_year = year;
			db_tm1.tm_mon = db_tm2.tm_mon = mon;

			if (statbuf.st_size < DBRECORDSIZE)
				format_err("file %s (file is too small)", path);
			
			lock_db_file_until_end(path, fileno(fp), -DBRECORDSIZE, SEEK_END);

			for (prev_mday = 0, lineno = 0;;) {
				struct tm	prev_db_tm2;

				if ( (ret = fread(oneline, sizeof(char), DBRECORDSIZE, fp)) != DBRECORDSIZE) {
					if (ret < DBRECORDSIZE && ret > 0) {
						if (feof(fp) != 0)
							format_err("file %s (cannot recognize last line: file is too small).", path);
						err_exit("fread(%s): failed", path);
					}
					if (ret == 0) {
						if (feof(fp) != 0) /* EOF */
							break;
						else
							err_exit("fread(%s)", path);
					}
				}
				++lineno;
				
				if (REGEXEC(db_entry, oneline) != 0)
					format_err("file %s (line %u)", path, lineno);
				errno = 0;
				if (sscanf(oneline, "%d/%d:%d:%d-%d:%d:%d %qu",
				    &db_tm1.tm_mday,
				    &db_tm1.tm_hour, &db_tm1.tm_min, &db_tm1.tm_sec,
				    &db_tm2.tm_hour, &db_tm2.tm_min, &db_tm2.tm_sec,
				    &db_value) != 8)
					err_exit("%s (line %u): sscanf(\"%s\", %%d/%%d:%%d:%%d-%%d:%%d:%%d %%qu): failed", path, lineno, oneline);
				db_tm2.tm_mday = db_tm1.tm_mday;
				if (check_dates_flag) {
					if (check_date(&db_tm1, 1) < 0 ||
					    check_date(&db_tm2, 1) < 0)
						format_err("file %s (line %u): wrong value of timestamp %s", path, lineno, use_e_switch_msg);
					if (tmcmp(&db_tm1, &db_tm2) > 0 ||
					    prev_mday > db_tm1.tm_mday)
						format_err("file %s (line %u): wrong sequence of dates %s", path, lineno, use_e_switch_msg);
					if (prev_mday == db_tm1.tm_mday)
						if (tmcmp(&prev_db_tm2, &db_tm1) > 0)
							format_err("file %s (line %u): wrong sequence of dates %s", path, lineno, use_e_switch_msg);
					prev_db_tm2 = db_tm2;
				}
				if (use_second_timestamp_flag && tmcmp(&db_tm2, &tm2) > 0)
					break;
				if (tmcmp(&db_tm1, &tm1) < 0)
					continue;
				if (tmcmp(&db_tm1, &tm2) > 0)
					break;
				if (ac_per_day_flag) {
					if (prev_mday == 0) {
						++ndays;
						prev_mday = db_tm1.tm_mday;
						summary_per_day = db_value;
						uquad_max_cnt_per_day = 0;
					} else if (prev_mday != db_tm1.tm_mday) {
						++ndays;
						if ( (ac_list = realloc(ac_list, (nac_list + 1) * sizeof *ac_list)) == NULL)
							err_exit("realloc");
						if (asprintf(&ac_list[nac_list].date, "%d.%02d.%02d", year, mon, prev_mday) < 0)
							err_exit("asprintf");
						if ( (tmp = strlen(ac_list[nac_list].date)) > width_2_1)
							width_2_1 = tmp;
						if (asprintf(&ac_list[nac_list].bytes, "%qu", summary_per_day) < 0)
							err_exit("asprintf");
						if ( (tmp = strlen(ac_list[nac_list].bytes)) > width_2_2)
							width_2_2 = tmp;
						ac_list[nac_list].bytes_conv = conv_bcnt(&summary_per_day);
						if ( (tmp = strlen(ac_list[nac_list].bytes_conv)) > width_2_3)
							width_2_3 = tmp;
						ac_list[nac_list].uquad_max_cnt = uquad_max_cnt_per_day;
						++nac_list;
						prev_mday = db_tm1.tm_mday;
						summary_per_day = db_value;
						uquad_max_cnt_per_day = 0;
					} else {
						if (summary_per_day <= UQUAD_MAX - db_value)
							summary_per_day += db_value;
						else {
							++uquad_max_cnt_per_day;
							summary_per_day = UQUAD_MAX - summary_per_day;
							summary_per_day = db_value - summary_per_day;
						}
					}
				} else {
					++nrecords;
					if (prev_mday == 0 || prev_mday != db_tm1.tm_mday) {
						++ndays;
						prev_mday = db_tm1.tm_mday;
					}
					if ( (ac_list = realloc(ac_list, (nac_list + 1) * sizeof *ac_list)) == NULL)
						err_exit("realloc");
					if (asprintf(&ac_list[nac_list].date, "%d.%02d.%02d", year, mon, prev_mday) < 0)
						err_exit("asprintf");
					if ( (tmp = strlen(ac_list[nac_list].date)) > width_2_1)
						width_2_1 = tmp;
					if (asprintf(&ac_list[nac_list].bytes, "%qu", db_value) < 0)
						err_exit("asprintf");
					if ( (tmp = strlen(ac_list[nac_list].bytes)) > width_2_4)
						width_2_4 = tmp;
					ac_list[nac_list].bytes_conv = conv_bcnt(&db_value);
					if ( (tmp = strlen(ac_list[nac_list].bytes_conv)) > width_2_5)
						width_2_5 = tmp;
					ac_list[nac_list].uquad_max_cnt = uquad_max_cnt_per_day;
					ac_list[nac_list].h1 = db_tm1.tm_hour;
					ac_list[nac_list].m1 = db_tm1.tm_min;
					ac_list[nac_list].s1 = db_tm1.tm_sec;
					ac_list[nac_list].h2 = db_tm2.tm_hour;
					ac_list[nac_list].m2 = db_tm2.tm_min;
					ac_list[nac_list].s2 = db_tm2.tm_sec;
					++nac_list;
				}
				if (summary < UQUAD_MAX - db_value)
					summary += db_value;
				else {
					++u_quad_max_summary_cnt;
					summary = UQUAD_MAX - summary;
					summary = db_value - summary;
				}
			}
			if (fclose(fp) != 0) /* also release lock */
				err_exit("fclose(%s)", path);
			free(path);
			if (ac_per_day_flag && prev_mday != 0) {
				if ( (ac_list = realloc(ac_list, (nac_list + 1) * sizeof *ac_list)) == NULL)
					err_exit("realloc");
				if (asprintf(&ac_list[nac_list].date, "%d.%02d.%02d", year, mon, prev_mday) < 0)
					err_exit("asprintf");
				if ( (tmp = strlen(ac_list[nac_list].date)) > width_2_1)
					width_2_1 = tmp;
				if (asprintf(&ac_list[nac_list].bytes, "%qu", summary_per_day) < 0)
					err_exit("asprintf");
				if ( (tmp = strlen(ac_list[nac_list].bytes)) > width_2_2)
					width_2_2 = tmp;
				ac_list[nac_list].bytes_conv = conv_bcnt(&summary_per_day);
				if ( (tmp = strlen(ac_list[nac_list].bytes_conv)) > width_2_3)
					width_2_3 = tmp;
				ac_list[nac_list].uquad_max_cnt = uquad_max_cnt_per_day; 
				++nac_list;
			}
		}
	}

	unlock_whole_db();

	if (asprintf(&summary_str, "%qu", summary) < 0)
		err_exit("asprintf");
	summary_conv_str = conv_bcnt(&summary);
	if (ac_per_day_flag) {
		if ( (tmp = strlen(summary_str)) > width_2_2)
			width_2_2 = tmp;
		if ( (tmp = strlen(summary_conv_str)) > width_2_3)
			width_2_3 = tmp;
	} else {
		if ( (tmp = strlen(summary_str)) > width_2_4)
			width_2_4 = tmp;
		if ( (tmp = strlen(summary_conv_str)) > width_2_5)
			width_2_5 = tmp;
	}
	if (u_quad_max_summary_cnt != 0) {
		if (asprintf(&u_quad_max_str, "%qu", UQUAD_MAX) < 0)
			err_exit("asprintf");
		u_quad_max_conv_str = conv_bcnt(&uquad_max_ULL);
		if (ac_per_day_flag) {
			if ( (tmp = strlen(u_quad_max_str)) > width_2_2)
				width_2_2 = tmp;
			if ( (tmp = strlen(u_quad_max_conv_str)) > width_2_3)
				width_2_3 = tmp;
		} else {
			if ( (tmp = strlen(u_quad_max_str)) > width_2_4)
				width_2_4 = tmp;
			if ( (tmp = strlen(u_quad_max_conv_str)) > width_2_5)
				width_2_5 = tmp;
		}
	}

	format = "| %-*s | %-*s | %-*s | %-*s |\n";
	print_table_line(4, width_1_1, width_1_2, width_1_3, width_1_4);
	if (print_table_flag)
		printf(format, width_1_1, "Rule", width_1_2, "Info", width_1_3, "From", width_1_4, "To");
	print_table_line(4, width_1_1, width_1_2, width_1_3, width_1_4);
	if (print_table_flag)
		printf(format, width_1_1, rule, width_1_2, info != NULL ? info : "", width_1_3, tm1_ptr, width_1_4, tm2_ptr);
	else
		printf("%s %s %s %s\n", rule, info != NULL ? info : "", tm1_ptr, tm2_ptr);
	print_table_line(4, width_1_1, width_1_2, width_1_3, width_1_4);
	if (print_table_flag)
		printf("\n");

	if (ac_per_day_flag) {
		format = "| %-*s | %*s | %*s |\n";
		print_table_line(3, width_2_1, width_2_2, width_2_3);
		if (print_table_flag)
			printf(format, width_2_1, "Date", width_2_2, "Bytes", width_2_3, bcnt_conv_msg[bcnt_conv_flag]);
		print_table_line(3, width_2_1, width_2_2, width_2_3);
		for (i = 0; i < nac_list; ++i) {
			if (ac_list[i].uquad_max_cnt) {
				if (print_table_flag)
					printf(format, width_2_1, ac_list[i].date, width_2_2, u_quad_max_str, width_2_3, u_quad_max_conv_str);
				else
					printf("%s %s %s\n", ac_list[i].date, u_quad_max_str, u_quad_max_conv_str);
				while (--ac_list[i].uquad_max_cnt) {
					if (print_table_flag)
						printf(format, width_2_1, "", width_2_2, u_quad_max_str, width_2_3, u_quad_max_conv_str);
					else
						printf("%s %s\n", u_quad_max_str, u_quad_max_conv_str);
				}
				if (print_table_flag)
					printf(format, width_2_1, "", width_2_2, ac_list[i].bytes, width_2_3, ac_list[i].bytes_conv);
				else
					printf("%s %s\n", ac_list[i].bytes, ac_list[i].bytes_conv);
			} else {
				if (print_table_flag)
					printf(format, width_2_1, ac_list[i].date, width_2_2, ac_list[i].bytes, width_2_3, ac_list[i].bytes_conv);
				else
					printf("%s %s %s\n", ac_list[i].date, ac_list[i].bytes, ac_list[i].bytes_conv);
			}
		}
		if (ac_list)
			print_table_line(3, width_2_1, width_2_2, width_2_3);
		while (u_quad_max_summary_cnt--) {
			if (print_table_flag)
				printf(format, width_2_1, "", width_2_2, u_quad_max_str, width_2_3, u_quad_max_conv_str);
			else
				printf("%s %s\n", u_quad_max_str, u_quad_max_conv_str);
		}
		if (print_table_flag)
			printf(format, width_2_1, "", width_2_2, summary_str, width_2_3, summary_conv_str);
		else
			printf("%s %s\n", summary_str,  summary_conv_str);
		print_table_line(3, width_2_1, width_2_2, width_2_3);
		if (print_table_flag)
			printf(" * %u day%s *\n", ndays,
			    ndays == 1 ? "" : "s");
	} else {
		format = "| %-*s | %-*s | %-*s | %*s | %*s |\n";
		print_table_line(5, width_2_1, width_2_2, width_2_3, width_2_4, width_2_5);
		if (print_table_flag)
			printf(format, width_2_1, "Date", width_2_2, "From", width_2_3, "To", width_2_4, "Bytes", width_2_5, bcnt_conv_msg[bcnt_conv_flag]);
		print_table_line(5, width_2_1, width_2_2, width_2_3, width_2_4, width_2_5);
		for (i = 0; i < nac_list; ++i) {
			if (print_table_flag)
				printf("| %-*s | %02d:%02d:%02d | %02d:%02d:%02d | %*s | %*s |\n",
				    width_2_1, ac_list[i].date,
				    ac_list[i].h1, ac_list[i].m1, ac_list[i].s1,
				    ac_list[i].h2, ac_list[i].m2, ac_list[i].s2,
				    width_2_4, ac_list[i].bytes, width_2_5, ac_list[i].bytes_conv);
			else
				printf("%s %02d:%02d:%02d %02d:%02d:%02d %s %s\n",
				    ac_list[i].date,
				    ac_list[i].h1, ac_list[i].m1, ac_list[i].s1,
				    ac_list[i].h2, ac_list[i].m2, ac_list[i].s2,
				    ac_list[i].bytes, ac_list[i].bytes_conv);
		}
		if (ac_list)
			print_table_line(5, width_2_1, width_2_2, width_2_3, width_2_4, width_2_5);
		while (u_quad_max_summary_cnt--) {
			if (print_table_flag)
				printf(format, width_2_1, "", width_2_2, "", width_2_3, "", width_2_4, u_quad_max_str, width_2_5, u_quad_max_conv_str);
			else
				printf("%s %s\n", u_quad_max_str, u_quad_max_conv_str);
		}
		if (print_table_flag)
			printf(format, width_2_1, "", width_2_2, "", width_2_3, "", width_2_4, summary_str, width_2_5, summary_conv_str);
		else
			printf("%s %s\n", summary_str,  summary_conv_str);
		print_table_line(5, width_2_1, width_2_2, width_2_3, width_2_4, width_2_5);
		if (print_table_flag)
			printf(" * %u record%s, %u day%s *\n", nrecords,
			    nrecords == 1 ? "" : "s", ndays, ndays == 1 ? "" : "s");
	}
}

/*
 * Read data from info file.
 * If limitname is NULL, then read info for rule rulename.
 */
static char *
get_info(const char *rulename, const char *limitname)
{
	int		len = 0;
	char		*path;
	FILE		*fp;

	static char	*buf = NULL;
	static size_t	bufsize;

	if (quiet_info_flag)
		return NULL;
	if (limitname == NULL) {
		if (asprintf(&path, "%s/%s/" INFOFILE, db_dir, rulename) < 0)
			err_exit("asprintf");
	} else {
		if (asprintf(&path, "%s/%s/" LIMITSDIR "/%s/" INFOFILE, db_dir, rulename, limitname) < 0)
			err_exit("asprintf");
	}
	if ( (fp = fopen(path, "r")) == NULL) {
		if (errno != ENOENT)
			err_exit("fopen(%s, \"r\")", path);
	} else {
		len = readline(&buf, &bufsize, fp, path);
		if (fclose(fp) != 0)
			err_exit("fclose(%s)", path);
	}
	free(path);
	return len == 0 ? NULL : buf;
}

/*
 * Compare two fields named name in struct name_list.
 * This function is called from qsort().
 */
static int
cmp_name_list(const void *p1, const void *p2)
{
	return strcmp(((const struct name_list *)p1)->name, ((const struct name_list *)p2)->name);
}

/*
 * Output all rules, which are allowed for user.
 * Option: -a
 */
static void
show_all_rules(void)
{
	int		nrules_flag = 0;
	u_int		nrules_list = 0;
	u_int		width_1, width_2, tmp, i;
	char		*info;
	char		format[] = "| %-*s | %-*s |\n";
	DIR		*dp;
	struct dirent	*dirp;
	struct name_list *rules_list = NULL;

	lock_whole_db_read();

	if ( (dp = opendir(db_dir)) == NULL)
		err_exit("opendir(%s)", db_dir);
	while ( (dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0 ||
		    strcmp(dirp->d_name, LOCKDBFILE) == 0)
			continue;
		nrules_flag = 1;
		if (can_access_rule(dirp->d_name) == 0)
			continue;
		info = get_info(dirp->d_name, (char *)NULL);
		if ( (rules_list = realloc(rules_list, (nrules_list + 1) * sizeof *rules_list)) == NULL)
			err_exit("realloc");
		if ( (rules_list[nrules_list].name = strdup(dirp->d_name)) == NULL)
			err_exit("strdup");
		if (info != NULL) {
			if ( (rules_list[nrules_list].info = strdup(info)) == NULL)
				err_exit("strdup");
		} else
			rules_list[nrules_list].info = NULL;
		++nrules_list;
	}

	unlock_whole_db();

	if (closedir(dp) < 0)
		err_exit("closedir(%s)", db_dir);
	if (nrules_list == 0) {
		if (nrules_flag == 0)
			warn_exit("no rules were found.");
		else
			warn_exit("you are not allowed to view any rule.");
	}

	/* Sort list by rules names */
	qsort(rules_list, nrules_list, sizeof *rules_list, cmp_name_list);

	width_1 = 4; /* Rule */
	width_2 = 4; /* Info */
	for (i = 0; i < nrules_list; ++i) {
		tmp = strlen(rules_list[i].name);
		if (width_1 < tmp)
			width_1 = tmp;
		if (rules_list[i].info != NULL) {
			tmp = strlen(rules_list[i].info);
			if (width_2 < tmp)
				width_2 = tmp;
		}
	}
	print_table_line(2, width_1, width_2);
	if (print_table_flag)
		printf(format, width_1, "Rule", width_2, "Info");
	print_table_line(2, width_1, width_2);
	for (i = 0; i < nrules_list; ++i) {
		if (print_table_flag)
			printf(format, width_1, rules_list[i].name, width_2, rules_list[i].info != NULL ? rules_list[i].info : "");
		else
			printf("%s %s\n", rules_list[i].name, rules_list[i].info != NULL ? rules_list[i].info : "");
	}
	print_table_line(2, width_1, width_2);
	if (print_table_flag)
		printf(" * %u rule%s *\n", nrules_list, nrules_list == 1 ? "" : "s");
}

/*
 * Output all limits for rule, which are allowed for user.
 * Option: [-x] -r <rule> -a
 */
static void
show_all_limits(void)
{
	DIR		*dp;
	char		*info, *limits_dir;
	struct name_list *limits_list = NULL;
	u_int		nlimits_list = 0;
	struct dirent	*dirp;
	u_int		width_1_1, width_1_2, width_2_1, width_2_2, tmp, i;
	char		format[] = "| %-*s | %-*s |\n";

	lock_whole_db_read();

	if (match_regex_flag) /* -x */
		get_rule_by_regex();
	else if (can_access_rule(rule) == 0)
		warn_exit(you_not_allowed_msg, rule);
		
	if (asprintf(&limits_dir, "%s/%s/" LIMITSDIR, db_dir, rule) < 0)
		err_exit("asprintf");
	if ( (dp = opendir(limits_dir)) == NULL)
		err_exit("opendir(%s)", limits_dir);

	while ( (dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
			continue;
		info = get_info(rule, dirp->d_name);
		if ( (limits_list = realloc(limits_list, (nlimits_list + 1) * sizeof *limits_list)) == NULL)
			err_exit("realloc");
		if ( (limits_list[nlimits_list].name = strdup(dirp->d_name)) == NULL)
			err_exit("strdup");
		if (info != NULL) {
			if ( (limits_list[nlimits_list].info = strdup(info)) == NULL)
				err_exit("strdup");
		} else
			limits_list[nlimits_list].info = NULL;
		++nlimits_list;
	}

	unlock_whole_db();

	if (closedir(dp) < 0)
		err_exit("closedir(%s)", db_dir);
	if (nlimits_list == 0)
		warn_exit("no limits were found for rule \"%s\".", rule);

	width_1_1 = 4; /* Rule */
	width_1_2 = 4; /* Info */
	tmp = strlen(rule);
	if (width_1_1 < tmp)
		width_1_1 = tmp;
	if ( (info = get_info(rule, (char *)NULL)) != NULL) {
		tmp = strlen(info);
		if (width_1_2 < tmp)
			width_1_2 = tmp;
	}

	width_2_1 = 5; /* Limit */
	width_2_2 = 4; /* Info */
	for (i = 0; i < nlimits_list; ++i) {
		tmp = strlen(limits_list[i].name);
		if (width_2_1 < tmp)
			width_2_1 = tmp;
		if (limits_list[i].info != NULL) {
			tmp = strlen(limits_list[i].info);
			if (width_2_2 < tmp)
				width_2_2 = tmp;
		}
	}

	/* Sort list by limits names */
	qsort(limits_list, nlimits_list, sizeof *limits_list, cmp_name_list);

	print_table_line(2, width_1_1, width_1_2);
	if (print_table_flag)
		printf(format, width_1_1, "Rule", width_1_2, "Info");
	print_table_line(2, width_1_1, width_1_2);
	if (print_table_flag)
		printf(format, width_1_1, rule, width_1_2, info != NULL ? info : "");
	else
		printf("%s %s\n", rule, info != NULL ? info : "");
	print_table_line(2, width_1_1, width_1_2);
	if (print_table_flag)
		printf("\n");

	print_table_line(2, width_2_1, width_2_2);
	if (print_table_flag)
		printf(format, width_2_1, "Limit", width_2_2, "Info");
	print_table_line(2, width_2_1, width_2_2);
	for (i = 0; i < nlimits_list; ++i) {
		if (print_table_flag)
			printf(format, width_2_1, limits_list[i].name, width_2_2, limits_list[i].info != NULL ? limits_list[i].info : "");
		else
			printf("%s %s\n", limits_list[i].name, limits_list[i].info != NULL ? limits_list[i].info : "");
	}
	print_table_line(2, width_2_1, width_2_2);
	if (print_table_line)
		printf(" * %u limit%s *\n", nlimits_list, nlimits_list == 1 ? "" : "s");
}

/*
 * Output accounting information for limit in rule.
 * Option: [-x] -r <rule> -l <limit>
 */
static void
print_limit_ac(void)
{
	char		*rule_info, *limit_info, *path, *format, *ptr;
	char		*byte_limit_str, *bytes_str, *byte_limit_conv_str, *bytes_conv_str;
	char		*buf = NULL;
	size_t		bufsize;
	u_quad_t	byte_limit, bytes;
	int		len, k;
	u_int		tmp, width_1, width_2, width_3, width_4;
	regex_t		reg_limit_line1, reg_limit_timestamp;
	FILE		*fp;
	struct stat	statbuf;
	struct timestamp {
		short		ts_is_set;
		struct tm	ts_tm;
		char		*date;
	}		ts_start, ts_zero, ts_reach, ts_expire, ts_exec1,
			ts_exec2, *ts_ptr;
	struct timestamp_arr {
		struct timestamp	*ptr;
		char			*status;
	}		ts_arr[6];
	char		*date_seq_msg = "date sequence in file %s %s";

	ts_arr[0].ptr = &ts_start;
	ts_arr[0].status = "Start";
	ts_arr[1].ptr = &ts_zero;
	ts_arr[1].status = "Zero";
	ts_arr[2].ptr = &ts_reach;
	ts_arr[2].status = "Reach";
	ts_arr[3].ptr = &ts_exec1;
	ts_arr[3].status = "Exec";
	ts_arr[4].ptr = &ts_expire;
	ts_arr[4].status = "Expire";
	ts_arr[5].ptr = &ts_exec2;
	ts_arr[5].status = "Exec";

	REGCOMP(limit_line1);
	REGCOMP(limit_timestamp);

	lock_whole_db_read();

	if (match_regex_flag) /* -x */
		get_rule_by_regex();
	else if (can_access_rule(rule) == 0)
		warn_exit(you_not_allowed_msg, rule);

	if ( (ptr = get_info(rule, (char *)NULL)) != NULL) {
		if ( (rule_info = strdup(ptr)) == NULL)
			err_exit("strdup");
	} else
		rule_info = NULL;
	limit_info = get_info(rule, limit);

	if (asprintf(&path, "%s/%s/" LIMITSDIR "/%s/" LIMITFILE, db_dir, rule, limit) < 0)
		err_exit("asprintf");

	if (lstat(path, &statbuf) < 0) {
		if (errno != ENOENT)
			err_exit("lstat(%s)", path);
		warn_exit("cannot find limit \"%s\" for rule \"%s\".", limit, rule);
	}
	if (!S_ISREG(statbuf.st_mode))
		errx_exit("%s should be a regular file.", path);
	if ( (fp = fopen(path, "r")) == NULL)
		err_exit("fopen(%s)", path);

	lock_db_file_until_end(path, fileno(fp), 0, SEEK_SET);

	len = readline(&buf, &bufsize, fp, path);
	if (len == 0)
		format_err("file %s", path);
	if (REGEXEC(limit_line1, buf) != 0)
		format_err("file %s (wrong first line).", path);

	errno = 0;
	if (sscanf(buf, "%qu %qu", &bytes, &byte_limit) != 2)
		err_exit("sscanf(\"%s\", %%qu %%qu): failed", path);

	if (asprintf(&bytes_str, "%qu", bytes) < 0)
		err_exit("asprintf");
	if (asprintf(&byte_limit_str, "%qu", byte_limit) < 0)
		err_exit("asprintf");
	byte_limit_conv_str = conv_bcnt(&byte_limit);
	bytes_conv_str = conv_bcnt(&bytes);

	ts_start.ts_is_set = ts_zero.ts_is_set = ts_reach.ts_is_set =
	    ts_expire.ts_is_set = ts_exec1.ts_is_set = ts_exec2.ts_is_set = 0;

	for (k = 0; k < 7; ++k) {
		len = readline(&buf, &bufsize, fp, path);
		if (len == 0 && feof(fp) != 0) {
			if (k == 0)
				format_err("file %s (should have at least two lines).", path);
			break;
		}
		if (len > 0 && k == 6)
			format_err("file %s (file is too big).", path);
		if (len == 0) /* XXX readline() can't return 0 without EOF */
			errx_exit("%s: read 0 bytes (%d line)", path, k + 2);
		if (REGEXEC(limit_timestamp, buf) != 0)
			format_err("file %s (%d line).", path, k + 2);

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
			format_err("file %s (line %d): unknown type of limit timestamp: `%c'.", path, k + 2, *buf);
		}
		if (ts_ptr == NULL)
			format_err("file %s (line %d): wrong order of timestamps.", path, k + 2);

		ts_ptr->ts_is_set = 1;

		errno = 0;
		if (sscanf(buf + 2, "%d.%d.%d/%d:%d:%d", &ts_ptr->ts_tm.tm_year,
		    &ts_ptr->ts_tm.tm_mon, &ts_ptr->ts_tm.tm_mday, &ts_ptr->ts_tm.tm_hour,
		    &ts_ptr->ts_tm.tm_min, &ts_ptr->ts_tm.tm_sec) != 6)
			err_exit("%s (line %d): sscanf(\"%s\", \"%%d.%%d.%%d/%%d:%%d:%%d\"): failed", path, k + 2, buf + 2);

		if (check_dates_flag && check_date(&ts_ptr->ts_tm, 0) < 0)
			format_err(date_seq_msg, path, use_e_switch_msg);
	}

	if (fclose(fp) != 0) /* also release lock */
		err_exit("fclose(%s)", path);

	unlock_whole_db();

	if (ts_zero.ts_is_set && ts_reach.ts_is_set)
		ts_zero.ts_is_set = 0;
	if (check_dates_flag) {
		ts_ptr = &ts_start;
		for (k = 0; k < 6; ++k) {
			if (ts_arr[k].ptr->ts_is_set) {
				if (tmcmp(&ts_arr[k].ptr->ts_tm, &ts_ptr->ts_tm) < 0)
					format_err(date_seq_msg, path, use_e_switch_msg);
				ts_ptr = ts_arr[k].ptr;
			}
		}
	}

	free(path);

	for (k = 0; k < 6; ++k) {
		if (ts_arr[k].ptr->ts_is_set)
			ts_arr[k].ptr->date = tm_str(&ts_arr[k].ptr->ts_tm);
	}

	width_1 = 4; /* Rule */
	width_2 = 9; /* Rule.Info */
	width_3 = 5; /* Limit */
	width_4 = 10; /* Limit.Info */

	if ( (tmp = strlen(rule)) > width_1)
		width_1 = tmp;
	if (rule_info != NULL)
		if ( (tmp = strlen(rule_info)) > width_2)
			width_2 = tmp;
	if ( (tmp = strlen(limit)) > width_3)
		width_3 = tmp;
	if (limit_info)
		if ( (tmp = strlen(limit_info)) > width_4)
			width_4 = tmp;

	print_table_line(4, width_1, width_2, width_3, width_4);
	format = "| %-*s | %-*s | %-*s | %-*s |\n";
	if (print_table_flag) {
		printf(format, width_1, "Rule", width_2, "Rule.Info", width_3, "Limit", width_4, "Limit.Info");
		print_table_line(4, width_1, width_2, width_3, width_4);
		printf(format, width_1, rule, width_2, rule_info != NULL ? rule_info : "",
		    width_3, limit, width_4, limit_info != NULL ? limit_info : "");
		print_table_line(4, width_1, width_2, width_3, width_4);
	} else
		printf("%s %s\n%s %s\n", rule, rule_info != NULL ? rule_info : "",
		    limit, limit_info != NULL ? limit_info : "");

	if (print_table_flag) {
		width_1 = 5; /* Bytes */
		if ( (tmp = strlen(bytes_str)) > width_1)
			width_1 = tmp;
		width_3 = strlen(bcnt_conv_msg[bcnt_conv_flag]); /* always > 'Cntr' */
		width_2 = width_4 = 10; /* Byte_limit, converted bcnt always < 'Byte_limit' */
		if ( (tmp = strlen(byte_limit_str)) > width_2)
			width_2 = tmp;
		if ( (tmp = strlen(bytes_conv_str)) > width_3)
			width_3 = tmp;
		if ( (tmp = strlen(byte_limit_conv_str)) > width_4)
			width_4 = tmp;
		printf("\n");
		print_table_line(4, width_1, width_2, width_3, width_4);
		printf(format, width_1, "Cntr", width_2, "Byte_limit", width_3, "Cntr", width_3, "Byte_limit");
		printf(format, width_1, "Bytes", width_2, "Bytes", width_3, bcnt_conv_msg[bcnt_conv_flag], width_4, bcnt_conv_msg[bcnt_conv_flag]);
		print_table_line(4, width_1, width_2, width_3, width_4);
		printf("| %*s | %*s | %*s | %*s |\n", width_1, bytes_str, width_2, byte_limit_str, width_3, bytes_conv_str, width_4, byte_limit_conv_str);
		print_table_line(4, width_1, width_2, width_3, width_4);
	} else
		printf("%s %s\n%s\n%s\n", bytes_str, byte_limit_str, bytes_conv_str, byte_limit_conv_str);

	width_1 = 6; /* Status */
	width_2 = 4; /* Date */
	for (k = 0; k < 6; ++k) {
		if (ts_arr[k].ptr->ts_is_set) {
			if ( (tmp = strlen(ts_arr[k].status)) > width_1)
				width_1 = tmp;
			if ( (tmp = strlen(ts_arr[k].ptr->date)) > width_2)
				width_2 = tmp;
		}
	}

	if (print_table_flag) {
		printf("\n");
		format = "| %-*s | %-*s |\n";
		print_table_line(2, width_1, width_2);
		printf(format, width_1, "Status", width_2, "Date");
		print_table_line(2, width_1, width_2);
	}
	for (k = 0; k < 6; ++k) {
		if (ts_arr[k].ptr->ts_is_set) {
			if (print_table_flag)
				printf(format, width_1, ts_arr[k].status, width_2, ts_arr[k].ptr->date);
			else
				printf("%s %s\n", ts_arr[k].status, ts_arr[k].ptr->date);
		}
	}
	print_table_line(2, width_1, width_2);
}

/*
 * Compare two struct summary_ac_list by rules names or
 * by values of byte counters.
 */
static int
cmp_summary_list(const void *p1, const void *p2)
{
	const struct summary_ac_list	*q1 = p1;
	const struct summary_ac_list	*q2 = p2;

	if (sort_by_cntr_flag) {
		if (sort_by_cntr_flag == 2) {
			q1 = p2;
			q2 = p1;
		}
		if (q1->uquad_max_cnt > q2->uquad_max_cnt)
			return 1;
		if (q1->uquad_max_cnt < q2->uquad_max_cnt)
			return -1;
		if (q1->bytes > q2->bytes)
			return 1;
		if (q1->bytes < q2->bytes)
			return -1;
	}
	return strcmp(q1->rule, q2->rule);
}

/*
 * Output summary accounting information for rule(s).
 * Options: [-x] -R <rule1> [-R <rule2> ... -R <rulen>]
 */
static void
print_rules_summary_ac(void)
{
	char		oneline[DBRECORDSIZE + 1];
	u_int		i, tmp, lineno;
	char		*path;
	struct tm	tm1, tm2, db_tm1, db_tm2;
	u_quad_t	db_value, summary;
	u_int		u_quad_max_found = 0, u_quad_max_summary_cnt;
	regex_t		reg_db_entry;
	u_int		width_1_1, width_1_2, width_2_1, width_2_2, width_2_3, width_2_4;
	char		*tm1_ptr, *tm2_ptr;
	char		*format, *info;
	int		year, ret, prev_mday;
	FILE		*fp;
	char		*u_quad_max_str, *u_quad_max_conv_str = NULL; /* initial value isn't used */
	struct stat	statbuf;
	struct summary_ac_list *summary_ac_list = NULL, *sptr;

	get_time_interval(&tm1, &tm2);

	REGCOMP(db_entry);

	width_2_1 = 4; /* Rule */
	width_2_2 = 4; /* Info */
	width_2_3 = 5; /* Bytes */
	width_2_4 = strlen(bcnt_conv_msg[bcnt_conv_flag]);

	oneline[DBRECORDSIZE] = '\0';

	lock_whole_db_read();

	if (match_regex_flag) /* -x */
		get_rules_by_regexs();
	else { /* no -x flag */
		nrules = nrules_opt;
		if ( (rules = malloc(nrules * sizeof *rules)) == NULL)
			err_exit("malloc");
		nrules = nrules_opt;
		for (i = 0; i < nrules; ++i)
			rules[i] = rules_opt[i].rule;
	}

	if ( (sptr = summary_ac_list = malloc(nrules * sizeof *summary_ac_list)) == NULL)
		err_exit("malloc");

	for (i = 0; i < nrules; ++i, ++sptr) {
		rule = rules[i];
		if (!match_regex_flag && can_access_rule(rule) == 0)
			warn_exit(you_not_allowed_msg, rule);

		summary = 0;
		u_quad_max_summary_cnt = 0;

		for (year = tm1.tm_year; year <= tm2.tm_year; ++year) {
			int	mon, mon1, mon2;

			mon1 = year == tm1.tm_year ? tm1.tm_mon : 1;
			mon2 = year == tm2.tm_year ? tm2.tm_mon : 12;
			for (mon = mon1; mon <= mon2; ++mon) {
				if (asprintf(&path, "%s/%s/%d/%02d", db_dir, rule, year, mon) < 0)
					err_exit("asprintf");
				if (lstat(path, &statbuf) < 0) {
					if (errno != ENOENT)
						err_exit("lstat(%s)", path);
					free(path);
					continue;
				}

				if (!S_ISREG(statbuf.st_mode))
					errx_exit("%s should be a regular file.", path);

				if (statbuf.st_size == 0) {
					/* file is empty */
					free(path);
					continue;
				}

				if ( (fp = fopen(path, "r")) == NULL)
					err_exit("fopen(%s, \"r\")", path);

				db_tm1.tm_year = db_tm2.tm_year = year;
				db_tm1.tm_mon = db_tm2.tm_mon = mon;

				if (statbuf.st_size < DBRECORDSIZE)
					format_err("file %s (file is too small).", path);

				lock_db_file_until_end(path, fileno(fp), -DBRECORDSIZE, SEEK_END);

				for (prev_mday = 0, lineno = 0;;) {
					struct tm	prev_db_tm2;

					if ( (ret = fread(oneline, sizeof(char), DBRECORDSIZE, fp)) != DBRECORDSIZE) {
						if (ret < DBRECORDSIZE && ret > 0) {
							if (feof(fp) != 0)
								format_err("file %s (cannot recognize last line: file is too small)", path);
							err_exit("fread(%s): failed", path);
						}
						if (ret == 0) {
							if (feof(fp) != 0) /* EOF */
								break;
							else
								err_exit("fread(%s)", path);
						}
					}
					++lineno;
					if (REGEXEC(db_entry, oneline) != 0)
						format_err("file %s (line %u)", path, lineno);
					errno = 0;
					if (sscanf(oneline, "%d/%d:%d:%d-%d:%d:%d %qu",
					    &db_tm1.tm_mday,
					    &db_tm1.tm_hour, &db_tm1.tm_min, &db_tm1.tm_sec,
					    &db_tm2.tm_hour, &db_tm2.tm_min, &db_tm2.tm_sec,
					    &db_value) != 8)
						err_exit("%s (line %u): sscanf(\"%s\", %%d/%%d:%%d:%%d-%%d:%%d:%%d %%qu): failed", path, lineno, oneline);
					db_tm2.tm_mday = db_tm1.tm_mday;
					if (check_dates_flag) {
						if (check_date(&db_tm1, 1) < 0 ||
						    check_date(&db_tm2, 1) < 0)
							format_err("file %s (line %u): wrong value of timestamp %s", path, lineno, use_e_switch_msg);
						if (tmcmp(&db_tm1, &db_tm2) > 0 ||
						    prev_mday > db_tm1.tm_mday)
							format_err("file %s (line %u): wrong sequence of dates %s", path, lineno, use_e_switch_msg);
						if (prev_mday == db_tm1.tm_mday)
							if (tmcmp(&prev_db_tm2, &db_tm1) > 0)
								format_err("file %s (line %u): wrong sequence of dates %s", path, lineno, use_e_switch_msg);
						prev_db_tm2 = db_tm2;
					}
					if (use_second_timestamp_flag && tmcmp(&db_tm2, &tm2) > 0)
						break;
					if (tmcmp(&db_tm1, &tm1) < 0)
						continue;
					if (tmcmp(&db_tm1, &tm2) > 0)
						break;
					prev_mday = db_tm1.tm_mday;
					if (summary < UQUAD_MAX - db_value)
						summary += db_value;
					else {
						++u_quad_max_summary_cnt;
						u_quad_max_found = 1;
						summary = UQUAD_MAX - summary;
						summary = db_value - summary;
					}
				}
				if (fclose(fp) != 0) /* also release lock */
					err_exit("fclose(%s)", path);
				free(path);
			}
		}

		sptr->rule = rule;
		if ( (tmp = strlen(rule)) > width_2_1)
			width_2_1 = tmp;
		if ( (info = get_info(rule, (char *)NULL)) != NULL) {
			if ( (sptr->info = strdup(info)) == NULL)
				err_exit("strdup");
			if ( (tmp = strlen(info)) > width_2_2)
				width_2_2 = tmp;
		} else
			sptr->info = NULL;
		sptr->bytes = summary;

		if (asprintf(&sptr->bytes_str, "%qu", summary) < 0)
			err_exit("asprintf");
		if ( (tmp = strlen(sptr->bytes_str)) > width_2_3)
			width_2_3 = tmp;
		sptr->bytes_conv_str = conv_bcnt(&summary);
		if ( (tmp = strlen(sptr->bytes_conv_str)) > width_2_4)
			width_2_4 = tmp;
		sptr->uquad_max_cnt = u_quad_max_summary_cnt;
	}

	unlock_whole_db();

	/* Sort summary by rules names or byte counters */
	qsort(summary_ac_list, nrules, sizeof *summary_ac_list, cmp_summary_list);

	if (u_quad_max_found) {
		if (asprintf(&u_quad_max_str, "%qu", UQUAD_MAX) < 0)
			err_exit("asprintf");
		u_quad_max_conv_str = conv_bcnt(&uquad_max_ULL);
			if ( (tmp = strlen(u_quad_max_str)) > width_2_3)
				width_2_3 = tmp;
			if ( (tmp = strlen(u_quad_max_conv_str)) > width_2_4)
				width_2_4 = tmp;
	}

	width_1_1 = 4; /* From */
	width_1_2 = 2; /* To */
	tm1_ptr = tm_str(&tm1);
	tm2_ptr = tm_str(&tm2);
	if ( (tmp = strlen(tm1_ptr)) > width_1_1)
		width_1_1 = tmp;
	if ( (tmp = strlen(tm2_ptr)) > width_1_2)
		width_1_2 = tmp;

	format = "| %-*s | %-*s |\n";
	print_table_line(2, width_1_1, width_1_2);
	if (print_table_flag)
		printf(format, width_1_1, "From", width_1_2, "To");
	print_table_line(2, width_1_1, width_1_2);
	if (print_table_flag)
		printf(format, width_1_1, tm1_ptr, width_1_2, tm2_ptr);
	else
		printf("%s %s\n", tm1_ptr, tm2_ptr);
	print_table_line(2, width_1_1, width_1_2);
	if (print_table_flag)
		printf("\n");

	print_table_line(4, width_2_1, width_2_2, width_2_3, width_2_4);
	format = "| %-*s | %-*s | %*s | %*s |\n";
	if (print_table_flag)
		printf(format, width_2_1, "Rule", width_2_2, "Info", width_2_3, "Bytes", width_2_4, bcnt_conv_msg[bcnt_conv_flag]);
	print_table_line(4, width_2_1, width_2_2, width_2_3, width_2_4);

	for (i = 0, sptr = summary_ac_list; i < nrules; ++i, ++sptr) {
		if (sptr->uquad_max_cnt) {
			if (print_table_flag)
				printf(format, width_2_1, sptr->rule, width_2_2, sptr->info != NULL ? sptr->info : "", width_2_3, u_quad_max_str, width_2_4, u_quad_max_conv_str);
			else
				printf("%s %s %s %s\n", sptr->rule, sptr->info != NULL ? sptr->info : "", u_quad_max_str, u_quad_max_conv_str);
			while (--sptr->uquad_max_cnt) {
				if (print_table_flag)
					printf(format, width_2_1, "", width_2_2, "", width_2_3, u_quad_max_str, width_2_4, u_quad_max_conv_str);
				else
					printf("%s %s\n", u_quad_max_str, u_quad_max_conv_str);
			}
			if (print_table_flag)
				printf(format, width_2_1, "", width_2_2, "", width_2_3, sptr->bytes_str, width_2_4, sptr->bytes_conv_str);
			else
				printf("%s %s\n", sptr->bytes_str, sptr->bytes_conv_str);
		} else {
			if (print_table_flag)
				printf(format, width_2_1, sptr->rule, width_2_2, sptr->info != NULL ? sptr->info : "", width_2_3, sptr->bytes_str, width_2_4, sptr->bytes_conv_str);
			else
				printf("%s %s %s %s\n", sptr->rule, sptr->info != NULL ? sptr->info : "", sptr->bytes_str, sptr->bytes_conv_str);
		}
		
	}
	print_table_line(4, width_2_1, width_2_2, width_2_3, width_2_4);
}

int
main(int argc, char *argv[])
{
	int	opt, show_all_flag = 0, k_flag = 0;

	opterr = 0;	/* don't allow getopt() to print own messages */
	while ( (opt = getopt(argc, argv, "abehkLnqtvxd:I:i:l:p:R:r:AKMGT")) != -1) {
		switch (opt) {
		case 'r':
			if (rule != NULL)
				errx_exit("only one -r option can be used");
			rule = optarg;
			break;
		case 'R':
			if ( (rules_opt = realloc(rules_opt, (nrules_opt + 1) * sizeof *rules_opt)) == NULL)
				err_exit("realloc");
			if ( (rules_opt[nrules_opt].rule = strdup(optarg)) == NULL)
				err_exit("strdup");
			++nrules_opt;
			break;
		case 'i':
			time_interval = optarg;
			break;
		case 'I':
			time_interval = optarg;
			use_second_timestamp_flag = 1;
			break;
		case 'l':
			if (limit != NULL)
				errx_exit("only one -l option can be used");
			limit = optarg;
			break;
		case 'p':
			time_back = optarg;
			break;
		case 'a':
			show_all_flag = 1;
			break;
		case 'd':
			db_dir = optarg;
			break;
		case 't':
			ac_per_day_flag = 0;
			break;
		case 'A':
			bcnt_conv_flag = Complete;
			break;
		case 'K':
			bcnt_conv_flag = Kbyte;
			break;
		case 'M':
			bcnt_conv_flag = Mbyte;
			break;
		case 'G':
			bcnt_conv_flag = Gbyte;
			break;
		case 'T':
			bcnt_conv_flag = Tbyte;
			break;
		case 'b':
			sort_by_cntr_flag = sort_by_cntr_flag == 1 ? 2 : 1;
			break;
		case 'k':
			k_flag = 1;
			break;
		case 'e':
			check_dates_flag = 0;
			break;
		case 'L':
			lock_db_flag = 1;
			break;
		case 'x':
			match_regex_flag = 1;
			break;
		case 'n':
			print_table_flag = 0;
			break;
		case 'q':
			quiet_info_flag = 1;
			break;
		case 'v':
			show_version();
			return 0;
		case 'h':
			show_usage(argv[0]);
			return 0;
		case '?':
			errx_exit("invalid switch -%c", optopt);
			/* NOTREACHED */
		default:
			err_exit("getopt");
		}
	}

	if (optind < argc)
		errx_exit("non-switch argument \"%s\"", argv[optind]);

	if (argc == 1)
		warn_exit("you should specify at least one switch.\nUse the -h switch to view help message.");
	if (limit != NULL && rule == NULL)
		errx_exit("the -l option must be used with the -r option.");
	if ((show_all_flag && rule != NULL && limit != NULL) || (limit != NULL && !ac_per_day_flag) ||
	    (rules_opt != NULL && (rule != NULL || limit != NULL || show_all_flag || !ac_per_day_flag)))
		errx_exit("given combination of switches and/or options is senseless.");

	if (bcnt_conv_flag == Complete) {
		if (k_flag) {
			kbyte = KBYTE10;
			mbyte = MBYTE10;
			gbyte = GBYTE10;
			tbyte = TBYTE10;
		}
		conv_bcnt = conv_bcnt_completely;
	} else {
		bcnt_conv_div = bcnt_conv_coef[k_flag][bcnt_conv_flag].div;
		bcnt_conv_add = bcnt_conv_coef[k_flag][bcnt_conv_flag].add;
		conv_bcnt = conv_bcnt_round;
	}


	if (match_regex_flag)
		prepare_match_regex();

	set_sighandlers();

	my_uid = getuid();

	if (show_all_flag) {
		/* -a */
		if (rule == NULL)
			show_all_rules();
		else /* -r */
			show_all_limits();
	} else if (rule != NULL) {
		/* -r */
		if (limit != NULL) /* -l */
			print_limit_ac();
		else
			print_rule_ac();
	} else if (rules_opt != NULL)
		/* -R */
		print_rules_summary_ac();
	else
		warn_exit("nothing to do with such options.");
	return 0;
}

/*
 * Output version number (-v and -h).
 */
static void
show_version(void)
{
	printf(IPASTAT_MSG", version %s (%s)\n", Version, System);
}

/*
 * Output help message.
 */
static void
show_usage(char *envprogname)
{
	char	*prog;

	if ( (prog = strrchr(envprogname, '/')) != NULL)
		++prog;
	else
		prog = envprogname;
	show_version();
	printf("\
Usage: %s [-abhkLnqtvx] [-AKMGT] [-d <db-directory>]\n\
	       [-p <time-back>] [-I|i <time-interval>]\n\
	       [-R|r <rule> [-l <limit>]]\n\
   -a\tPrint names of all rules, which user can view or print names of\n\
   \tall limits for the rule specified in the -r option\n\
   -b\tSort summary accounting information by byte counters,\n\
   \ttwo switches -bb give reverse order of sorting. This switch can be\n\
   \tused with some -R options\n\
   -d <db-direcory>\n\
   \tUse given <db-directory> instead of using default database\n\
   \tdirectory %s\n\
   -e\tDo not check dates in accounting files, output all accounting\n\
   \tinformation even if there are errors in accounting files\n\
   -h\tOutput this help message\n\
   -I|i <time-interval>\n\
   \tSpecify <time-interval> for output accounting information. See\n\
   \tipastat(8) manual page about difference between these two options\n\
   -k\tAssume that 1K is equal to 1000 bytes and so on\n\
   -L\tUse database locking feature\n\
   -n\tDo not indent information and print tables when output results.\n\
   \tUse this option if you want to parse output of ipastat(8)\n\
   -p <time-back>\n\
   \t\"Go back\" in time, then output statistics. This option can be used\n\
   \twith the -i or -I option\n\
   -q\tDo not read and output any \"info\" files\n\
   -R <rule>\n\
   \tOutput summary accounting information for specified <rule>,\n\
   \tit is possible to specify some -R options in one command line\n\
   -r <rule> [-l <limit>]\n\
   \tOutput accounting information for specified <rule>, statistics is\n\
   \toutput  per day. Or output accounting information for specified\n\
   \t<limit> for <rule>\n\
   -t\tOutput accounting information for the rule per timestamp\n\
   -v\tShow version number and exit\n\
   -x\tTreat rule names as POSIX regular expressions\n\
   -A\tConvert values of byte counters to Tbytes, Gbytes, Mbytes,\n\
   \tKbytes and bytes (convert as much as possible)\n\
   -K|M|G|T\n\
   \tConvert values of byte counters to Kbytes, Mbytes (this is default)\n\
   \tGbytes or Tbytes\n", prog, db_dir);
}

/*
 * Read one line from fp, return number of characters in the line or
 * -1 if an error occured. *size is equal to #bytes previously allocated
 * in *strp by malloc(). If there is not enough space in *strp, then readline()
 * reallocates *strp and updates *size.
 *
 * This is a wrapper for fgets() function with some extensions.
 */
static int
readline(char **strp, size_t *size, FILE *fp, const char *filename)
{
#define CHUNK_SIZE 100

#if (CHUNK_SIZE <= 1)
# error Macro CHUNK_SIZE should be greater than 1
#endif

	char		*s;
	size_t		can_nread;	/* #bytes to read in next fgets */
	size_t		len;		/* length of read string */
	size_t		nread = 0;	/* how many bytes we read */

	if (*strp == NULL) {
		if ( (*strp = malloc(CHUNK_SIZE)) == NULL)
			err_exit("malloc");
		*size = CHUNK_SIZE;
	}
	for (s = *strp, can_nread = *size; ;) {
		if (fgets(s, can_nread, fp) == NULL) {
			if (feof(fp) != 0)
				break;	/* EOF */
			err_exit("fgets(%s)", filename);
		}
		len = strlen(s);
		if (len > 0) {
			nread += len;
			if (s[len - 1] == '\n')
				break;
		}
		if ( (s = realloc(*strp, *size + CHUNK_SIZE)) == NULL)
			err_exit("realloc");
		*strp = s;
		*size += can_nread = CHUNK_SIZE;
		s += nread;
	}
	return nread;
}

/*
 * Output message, error message and exit.
 */
static void
err_exit(const char *message, ...)
{
	int	errno_save = errno;
	va_list	ap;

	va_start(ap, message);
	fflush(stdout);
	fprintf(stderr, "\nError: ");
	vfprintf(stderr, message, ap);
	if (errno_save > 0)
		fprintf(stderr, ": %s", strerror(errno_save));
	fprintf(stderr, "\n\n");
	va_end(ap);
	exit(1);
}

/*
 * Output message and exit.
 */
static void
errx_exit(const char *message, ...)
{
	va_list	ap;

	va_start(ap, message);
	fflush(stdout);
	fprintf(stderr, "\nError: ");
	vfprintf(stderr, message, ap);
	fprintf(stderr, "\n\n");
	va_end(ap);
	exit(1);
}

/*
 * Output message and exit.
 */
static void
warn_exit(const char *message, ...)
{
	va_list	ap;

	va_start(ap, message);
	printf("\nWarning: ");
	vprintf(message, ap);
	printf("\n\n");
	va_end(ap);
	exit(1);
}

/*
 * Output error message about wrong format of something and exit.
 */
static void
format_err(const char *message, ...)
{
	va_list		ap;

	va_start(ap, message);
	fflush(stdout);
	fprintf(stderr, "\nError: wrong format of ");
	vfprintf(stderr, message, ap);
	fprintf(stderr, "\n\n");
	va_end(ap);
	exit(1);
}


/*
 * Handler for SIGALRM.
 */
static void
sig_alrm(int signo)
{
	longjmp(env_alrm, 1); 
}

/*
 * Ignore SIGTSTP and SIGTTOU.
 * Set signal handler for SIGALRM.
 */
static void
set_sighandlers(void)
{
	struct sigaction	act;

	if (signal(SIGTSTP, SIG_IGN) == SIG_ERR)
		err_exit("signal(SIGTSTP)");
	if (signal(SIGTTOU, SIG_IGN) == SIG_ERR)
		err_exit("signal(SIGTTOU)");
	if (lock_db_flag) {
		act.sa_flags = 0;
		sigemptyset(&act.sa_mask);
		act.sa_handler = sig_alrm;
		if (sigaction(SIGALRM, &act, (struct sigaction *)NULL) < 0)
			err_exit("sigaction(SIGALRM)");
	}
}

/*
 * Obtain "read" lock on whole database.
 */
static void
lock_whole_db_read(void)
{
	if (lock_db_flag) {
		if (asprintf(&lock_db_file, "%s/%s", db_dir, LOCKDBFILE) < 0)
			err_exit("asprintf");

		if ( (lock_db_fd = open(lock_db_file, O_RDONLY)) < 0)
			err_exit("open(%s)", lock_db_file);

		if (setjmp(env_alrm) != 0)
			warn_exit("cannot lock file %s (whole database) during %u seconds",
			    lock_db_file, LOCK_WAIT_TIME);

		alarm(LOCK_WAIT_TIME);
		if (readw_lock(lock_db_fd, 0, SEEK_SET, 0) < 0)
			err_exit("readw_lock(%s)", lock_db_file);
		alarm(0);
	}
}

/*
 * Unlock whole database.
 */
static void
unlock_whole_db(void)
{
	if (lock_db_flag) {
		if (close(lock_db_fd) < 0)
			err_exit("close(%s)", lock_db_file);
		free(lock_db_file);
	}
}

/*
 * Obtain "read" lock on file from start to the end of file. Starting offset
 * is measured from the position specified by whence parameter (SEEK_CUR,
 * SEEK_SET and SEEK_END).
 */
static void
lock_db_file_until_end(const char *file, int fd, int start, short whence)
{
	if (lock_db_flag) {
		if (setjmp(env_alrm) != 0)
			warn_exit("cannot lock file %s during %u seconds.", file, LOCK_WAIT_TIME);
		alarm(LOCK_WAIT_TIME);
		if (readw_lock(fd, start, whence, 0) < 0)
			err_exit("readw_lock(%s)", file);
		alarm(0);
	}
}

/*
 * Build REs for get_rule_by_regex() and get_rules_by_regexs() functions.
 */
static void
prepare_match_regex(void)
{
	if (rule != NULL)
		if ( (re_errcode = regcomp(&rule_re, rule, REG_EXTENDED|REG_NOSUB)) != 0) {
			re_form_errbuf();
			errx_exit("regcomp(\"%s\"): %s", rule, re_errbuf);
		}
	if (rules_opt != NULL) {
		u_int		i;
		struct rules_opt *ptr;

		for (i = 0, ptr = rules_opt; i < nrules_opt; ++ptr, ++i)
			if ( (re_errcode = regcomp(&ptr->rule_re, ptr->rule, REG_EXTENDED|REG_NOSUB)) != 0) {
				re_form_errbuf();
				errx_exit("regcomp(\"%s\"): %s", ptr->rule, re_errbuf);
			}
	}
}
