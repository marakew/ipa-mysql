/*-
 * Copyright (c) 2000-2002 Andrey Simonenko
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
  "@(#)$Id: common.c,v 1.4.2.1 2003/11/11 10:23:42 simon Exp $";
#endif /* !lint */

#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <regex.h>

#include "common.h"
#include "version.h"
#include "system.h"


const char	Version[] = IPA_VERSION;
const char	System[] = BUILT_FOR_SYSTEM;

/* buffer for error message for regerror() */
int		re_errcode;
char		re_errbuf[RE_ERRBUF_SIZ];


/*
 * Strip all characters before first white-space character in a string,
 * if it doesn't exists then return original string.
 */
char *
skip_first_space(char *s)
{
	char	*ptr;

	ptr = strchr(s, ' ');
	return ptr != NULL ? ptr + 1 : s;
}

/*
 * Strip a string after last found white-space character.
 */
void
last_space_to_nul(char *s)
{
	char	*ptr;

	ptr = strrchr(s, ' ');
	if (ptr != NULL)
		*ptr = '\0';
	else
		*s = '\0';	/* no white-space at the end of a string */
}

/*
 * Compare two struct tm tm1 and tm2.
 * if (tm1 == tm2)
 *	return 0;
 * if (tm1 > tm2)
 *	return 1;
 * if (tm1 < tm2)
 *	return -1;
 */
int
tmcmp(const struct tm *tm1, const struct tm *tm2)
{
	/* don't use mktime(), because there can be problem with time zone
	   and summer time */
	if (tm1->tm_year > tm2->tm_year)
		return 1;
	if (tm1->tm_year == tm2->tm_year) {
		if (tm1->tm_mon > tm2->tm_mon)
			return 1;
		if (tm1->tm_mon == tm2->tm_mon) {
			if (tm1->tm_mday > tm2->tm_mday)
				return 1;
			if (tm1->tm_mday == tm2->tm_mday) {
				if (tm1->tm_hour > tm2->tm_hour)
					return 1;
				if (tm1->tm_hour == tm2->tm_hour) {
					if (tm1->tm_min > tm2->tm_min)
						return 1;
					if (tm1->tm_min == tm2->tm_min) {
						if (tm1->tm_sec > tm2->tm_sec)
							return 1;
						if (tm1->tm_sec == tm2->tm_sec)
							return 0;
					}
				}
			}
		}
	}
	return -1;
}

/*
 * Check date for human correct values. Assume time 24:00:00 also as correct
 * if allow_24_hours is not zero.
 */
int
check_date(const struct tm *ptr, int allow_24_hours)
{
	if ( ptr->tm_mon == 0 || ptr->tm_mon > 12 ||
	     ptr->tm_mday > 31 || ptr->tm_mday == 0 ||
	     ( (ptr->tm_hour > 23 || ptr->tm_min > 59 || ptr->tm_sec > 59) &&
               !(allow_24_hours && ptr->tm_hour == 24 && ptr->tm_min == 0 && ptr->tm_sec == 0) ) )
		return -1;
	return 0;
}

/*
 * Lock region, wrapper for fcntl() locking.
 * Shoud be used in *_lock() macros.
 */
int
lock_reg(int fd, int cmd, int type, off_t start, short whence, off_t len)
{
	struct flock	lock;

	lock.l_type = type;
	lock.l_start = start;
	lock.l_whence = whence;
	lock.l_len = len;
	return fcntl(fd, cmd, &lock);
}

/*
 * Form error message in re_errbuf according to re_errcode by
 * regerror() function.
 */
void
re_form_errbuf(void)
{
	regerror(re_errcode, (regex_t *)NULL, re_errbuf, sizeof re_errbuf);
}
