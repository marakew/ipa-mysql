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
 *
 *   @(#)$Id: common.h,v 1.4.2.2 2003/11/11 10:23:42 simon Exp $
 */

#ifndef IPA_COMMON_H
#define IPA_COMMON_H


#define REGEXEC(re, str) regexec(&reg_ ## re, str, 0, (regmatch_t *)NULL, 0)

#define DBRECORDSIZE	42
#define DBCOUNTEROFF	30
#define DBCOUNTERSIZE	29
/* Example for db entry
01/01:01:01-02:02:02 12345678901234567890\n
            ^13 characters               ^42 characters
*/

#define LIMIT_LINE1_SIZE	(20 + 1 + 20 + 1)
#define LIMIT_COUNTER_SIZE	(20)
#define LIMIT_TIMESTAMP_SIZE	(1 + 1 + 4 + 16)
/* Example for timestamp:
s 2000.01.01/01:01:01\n
		     >=22 characters
*/

#define LIMIT_STARTED	's'
#define LIMIT_REACHED	'r'
#define LIMIT_ZEROED	'z'
#define LIMIT_EXPIRED	'e'
#define LIMIT_EXECUTED	'x'


#define pat_db_entry	"^[[:digit:]]{2}/[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2}-[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2} [[:digit:]]{20}\n$"
#define pat_limit_line1	"^[[:digit:]]{20} [[:digit:]]{20}\n$"
#define pat_limit_timestamp "^[szrex] [[:digit:]]{4,}.[[:digit:]]{2}.[[:digit:]]{2}/[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2}\n$"

extern const char Version[];
extern const char System[];
extern char	*skip_first_space(char *);
extern void	last_space_to_nul(char *);
extern int	tmcmp(const struct tm *, const struct tm *);
extern int	check_date(const struct tm *, int);
extern int	lock_reg(int, int, int, off_t, short, off_t);

#define RE_ERRBUF_SIZ 100
extern int	re_errcode;
extern char	re_errbuf[RE_ERRBUF_SIZ];

extern void	re_form_errbuf(void);

#define readw_lock(fd, start, whence, len)	\
	lock_reg(fd, F_SETLKW, F_RDLCK, start, whence, len)
#define writew_lock(fd, start, whence, len)	\
	lock_reg(fd, F_SETLKW, F_WRLCK, start, whence, len)
#define un_lock(fd, start, whence, len)		\
	lock_reg(fd, F_SETLK, F_UNLCK, start, whence, len)

#endif /* IPA_COMMON_H */
