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
 *  @(#)$Id: db.h,v 1.4.2.3 2003/07/08 08:30:01 simon Exp $
 */

#ifndef IPA_DB_H
#define IPA_DB_H

#include <sys/types.h>
#include <regex.h>

#include "rules.h"

#define DB_DIR_PERM_UG		(S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP)/* 0550 */
#define DB_DIR_PERM_U		(S_IRUSR|S_IXUSR)		 /* 0500 */

#define DB_FILE_PERM_UG		(S_IRUSR|S_IRGRP)		 /* 0440 */
#define DB_FILE_PERM_U		(S_IRUSR)			 /* 0400 */

#define UPDATE_DB_TIME_DEF	(5 * MINUTE)	/* default value for the "update_db_time" parameter */
#define LOCK_WAIT_TIME_DEF	(5)		/* default value for the "lock_wait_time" parameter */

extern char	*db_dir, *db_dir_default;
extern int	lock_db;
extern u_int	lock_wait_time;
extern int	curwday;
extern time_t	curr_time;
extern struct tm curr_tm;
extern regex_t	reg_limit_line1, reg_limit_timestamp;

extern int	init_db(void);
extern int	update_db(const struct rule *, const u_quad_t *);
extern int	append_db(struct rule *, const u_quad_t *);
extern int	create_db_dir(const char *, const struct rule *);
extern FILE	*create_db_file(const char *, const struct rule *);
extern int	check_db_dir(const char *, const struct rule *);
extern int	check_db_file(const char *, const struct rule *);
extern int	build_db_regexes(void);
extern int	lock_db_file_until_end(const char *, int, short);
extern int	unlock_db_file(const char *, int);

#endif /* !IPA_DB_H */
