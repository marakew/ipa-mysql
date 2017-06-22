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
  "@(#)$Id: db.c,v 1.6.2.7 2003/07/08 08:30:01 simon Exp $";
#endif /* !lint */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <regex.h>

#include "db.h"

#include "ipa.h"
#include "common.h"
#include "config.h"
#include "debug.h"
#include "path.h"
#include "rules.h"

/* PERMMASK allows to get just permission bits from st_mode (struct stat) field
   PERMMASK(x) = x & 0777 */
#define PERMMASK(x)	((x) & (S_IRWXU|S_IRWXG|S_IRWXO))

char		*db_dir;			/* global { db_dir }, main database directory */
char		*db_dir_default = DBDIR;	/* defaul database directory */
int		lock_db;			/* global { lock_db } */
u_int		lock_wait_time;			/* global { lock_wait_time } */

int		curwday;			/* Current week day. */
time_t		curr_time;			/* current UTC time in seconds */
struct tm	curr_tm;			/* current localtime */

regex_t		reg_limit_line1, reg_limit_timestamp;

#define MAIN_DB_DIR_PERM	(DB_DIR_PERM_UG|S_IROTH|S_IXOTH)/* 0555 */

#define LOCK_DB_FILE_PERM	(DB_FILE_PERM_UG|S_IROTH)	/* 0444 */

static char	*lock_db_file = NULL;		/* "lock db" file absolute pathname */
static int	lock_db_fd;			/* "lock db" FD */
static int	db_file_is_locked = 0;		/* ==1 if current database file is locked */
static jmp_buf	env_alrm;

static struct sigaction sig_alrm2_act, save_sig_alrm;

/*
 * Yet another ALRM signal handler.
 * Should be used to avoid race condition in "lock" functions.
 */
static void
sig_alrm2(int signo)
{
	longjmp(env_alrm, 1);
}

/*
 * Init settings for SIGALRM handler.
 */
static void
init_sig_alrm2(void)
{
	sig_alrm2_act.sa_flags = 0;
	sigemptyset(&sig_alrm2_act.sa_mask);
	sigaddset(&sig_alrm2_act.sa_mask, SIGHUP);
	sigaddset(&sig_alrm2_act.sa_mask, SIGTERM);
	sigaddset(&sig_alrm2_act.sa_mask, SIGCHLD);
	sigaddset(&sig_alrm2_act.sa_mask, SIGUSR1);
	if (debug)
		sigaddset(&sig_alrm2_act.sa_mask, SIGINT);
	sig_alrm2_act.sa_handler = sig_alrm2;
}

/*
 * Setup new SIGALRM handler.
 */
static int
set_sig_alrm2(void)
{
	if (sigaction(SIGALRM, &sig_alrm2_act, &save_sig_alrm) < 0) {
		syslog(LOG_ERR, "sigaction(SIGALRM), set new handler: %m");
		return -1;
	}
	return 0;
}

/*
 * Restore old SIGALRM handler.
 */
static int
reset_sig_alrm(void)
{
	if (sigaction(SIGALRM, &save_sig_alrm, (struct sigaction *)NULL) < 0) {
		syslog(LOG_ERR, "sigaction(SIGALRM), restore handler: %m");
		return -1;
	}
	return 0;
}

/*
 * Obtain "write" lock on a file from the starting offset 0 bytes
 * until the end of a file. The starting offset is measured from the position
 * specified by whence parameter (SEEK_CUR, SEEK_SET and SEEK_END).
 */
int
lock_db_file_until_end(const char *file, int fd, short whence)
{
	if (set_sig_alrm2() < 0)
		return -1;
	if (setjmp(env_alrm) != 0) {
		syslog(LOG_WARNING, "cannot lock file %s during %u seconds, give up",
		    file, lock_wait_time);
		db_file_is_locked = 0;
		if (reset_sig_alrm() < 0)
			return -1;
		return 0;
	}
	if (debug_lock > 0)
		syslog(LOG_INFO, "try to lock file %s (timeout %u seconds)",
		    file, lock_wait_time);
	alarm(lock_wait_time);
	if (writew_lock(fd, 0, whence, 0) < 0) {
		syslog(LOG_ERR, "writew_lock(%s): %m", file);
		return -1;
	}
	alarm(0);
	if (debug_lock > 0)
		syslog(LOG_INFO, "file %s is locked", file);
	if (reset_sig_alrm() < 0)
		return -1;
	db_file_is_locked = 1;
	return 0;
}

/*
 * Unlock whole file.
 */
int
unlock_db_file(const char *file, int fd)
{
	if (debug_lock > 0)
		syslog(LOG_INFO, "release lock on %s", file);
	if (un_lock(fd, 0, SEEK_SET, 0) < 0) {
		syslog(LOG_ERR, "un_lock(%s): %m", file);
		return -1;
	}
	db_file_is_locked = 0;
	return 0;
}

/*
 * Obtain exclusive lock on whole database.
 */
static int
lock_whole_db_write(void)
{
	if ( (lock_db_fd = open(lock_db_file, O_WRONLY)) < 0) {
		syslog(LOG_ERR, "open(%s, O_WRONLY): %m", lock_db_file);
		return -1;
	}
	return lock_db_file_until_end(lock_db_file, lock_db_fd, SEEK_SET);
}

/*
 * Unlock whole database.
 */
static int
unlock_whole_db(void)
{
	if (debug_lock > 0)
		syslog(LOG_INFO, "unlock_db: release lock on %s", lock_db_file);
	if (close(lock_db_fd) < 0) {
		syslog(LOG_ERR, "close(%s): %m", lock_db_file);
		return -1;
	}
	db_file_is_locked = 0;
	return 0;
}

/*
 * Update current record for *acp accounting rule in database.
 * value is equal to new value of counter.
 */
int
update_db(const struct rule *rule, const u_quad_t *value_ptr)
{
	if (fseek(rule->fp, (long)-DBCOUNTEROFF, SEEK_END) < 0) {
		syslog(LOG_ERR, "update_db: fseek(%s, -%d, SEEK_END): %m",
		    rule->filename, DBCOUNTEROFF);
		return -1;
	}

	if (lock_db && lock_db_file_until_end(rule->filename, rule->fd, SEEK_CUR) < 0)
		return -1;

	/* update second timestamp and counter */
	if (fprintf(rule->fp, "%02d:%02d:%02d %020qu",
	    curr_tm.tm_hour, curr_tm.tm_min, curr_tm.tm_sec, *value_ptr) != DBCOUNTERSIZE) {
		syslog(LOG_ERR, "update_db: fprintf(%s), failed: %m", rule->filename);
		return -1;
	}
	if (fflush(rule->fp) != 0) {
		syslog(LOG_ERR, "update_db: fflush(%s): %m", rule->filename);
		return -1;
	}
	
	if (db_file_is_locked && unlock_db_file(rule->filename, rule->fd) < 0)
		return -1;
	return 0;
}

/*
 * Append a new record for *rule accounting rule in database.
 * Update acp->newrec_time field.
 */
int
append_db(struct rule *rule, const u_quad_t *value_ptr)
{
	if (fseek(rule->fp, 0L, SEEK_END) < 0) {
		syslog(LOG_ERR, "append_db: fseek(%s, 0, SEEK_END): %m", rule->filename);
		return -1;
	}

	if (lock_db && lock_db_file_until_end(rule->filename, rule->fd, SEEK_CUR) < 0)
		return -1;

	if (fprintf(rule->fp, "%02d/%02d:%02d:%02d-%02d:%02d:%02d %020qu\n",
	    curr_tm.tm_mday,
	    curr_tm.tm_hour, curr_tm.tm_min, curr_tm.tm_sec,
	    curr_tm.tm_hour, curr_tm.tm_min, curr_tm.tm_sec,
	    *value_ptr) != DBRECORDSIZE) {
		syslog(LOG_ERR, "append_db: fprintf(%s), failed: %m", rule->filename);
		return -1;
	}
	/* newrec_time will be checked if "append_db_time" parameter was
	   specified in the configuration file for *rule rule */
	rule->newrec_time = curr_time + rule->append_db_time;
	if (fflush(rule->fp) != 0) {
		syslog(LOG_ERR, "append_db: fflush(%s): %m", rule->filename);
		return -1;
	}

	if (db_file_is_locked && unlock_db_file(rule->filename, rule->fd) < 0)
		return -1;
	return 0;
}

/*
 * Fix the mode and owner of the database directory.
 */
static int
fix_db_dir(const char *path, const struct rule *rule)
{
	if (chmod(path, rule->db_group.dir_mode) < 0) {
		syslog(LOG_ERR, "chmod(%s, 0%03o): %m", path, rule->db_group.dir_mode);
		return -1;
	}
	if (chown(path, 0, rule->db_group.group_id) < 0) {
		syslog(LOG_ERR, "chown(%s, 0, %ld): %m", path, rule->db_group.group_id);
		return -1;
	}
	return 0;
}

/*
 * Fix the mode and owner of the database file.
 */
static int
fix_db_file(const char *path, const struct rule *rule)
{
	if (chmod(path, rule->db_group.file_mode) < 0) {
		syslog(LOG_ERR, "chmod(%s, 0%03o): %m", path, rule->db_group.file_mode);
		return -1;
	}
	if (chown(path, 0, rule->db_group.group_id) < 0) {
		syslog(LOG_ERR, "chown(%s, 0, %ld): %m", path, rule->db_group.group_id);
		return -1;
	}
	return 0;
}

/*
 * Check database file.
 * Returns:
 *  0, if there is not such file;
 *  1, if file is present and it has correct owner and permission bits;
 * -1, if there are problems with owner or permissions bits, or if error occured.
 */
int
check_db_file(const char *path, const struct rule *rule)
{
	struct stat	statbuf;

	if (lstat(path, &statbuf) < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "lstat(%s): %m", path);
			return -1;
		}
		return 0;
	}
	if (!S_ISREG(statbuf.st_mode)) {
		syslog(LOG_ERR, "%s is expected to be a regular file", path);
		return -1;
	}
	if (statbuf.st_uid != 0) {
		syslog(LOG_ERR, "database file %s has wrong owner UID %d (it should be owned by root)",
		    path, statbuf.st_uid);
		return -1;
	}
	if (PERMMASK(statbuf.st_mode) != DB_FILE_PERM_U &&
	    PERMMASK(statbuf.st_mode) != DB_FILE_PERM_UG) {
		syslog(LOG_ERR, "database file %s has wrong permission bits 0%03o (they should be 0%03o or 0%03o)",
		    path, PERMMASK(statbuf.st_mode), DB_FILE_PERM_UG, DB_FILE_PERM_U);
		return -1;
	}
	if (PERMMASK(statbuf.st_mode) != rule->db_group.file_mode) {
		syslog(LOG_WARNING, "database file %s has incorrect permission bits 0%03o, fixing -> 0%03o",
		    path, PERMMASK(statbuf.st_mode), rule->db_group.file_mode);
		if (fix_db_file(path, rule) < 0)
			return -1;
	} else if (statbuf.st_gid != rule->db_group.group_id) {
		syslog(LOG_WARNING, "database file %s has wrong group owner GID %d (it should be GID %ld), fixing...",
		    path, statbuf.st_gid, rule->db_group.group_id);
		if (fix_db_file(path, rule) < 0)
			return -1;
	}
	return 1;
}

/*
 * Check database directory.
 * Returns:
 *  0, if there is not such directory;
 *  1, if directory is present and it has correct owner and permission bits;
 * -1, if there are problems with owner or permissions bits, or if error
 *     occured.
 */
int
check_db_dir(const char *path, const struct rule *rule)
{
	struct stat	statbuf;

	if (lstat(path, &statbuf) < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "lstat(%s): %m", path);
			return -1;
		}
		return 0;
	}
	if (!S_ISDIR(statbuf.st_mode)) {
		syslog(LOG_ERR, "%s is expected to be a directory", path);
		return -1;
	}

	if (statbuf.st_uid != 0) {
		syslog(LOG_ERR, "database directory %s has wrong owner UID %d (it should be owned by root)",
		    path, statbuf.st_uid);
		return -1;
	}
	if (PERMMASK(statbuf.st_mode) != DB_DIR_PERM_U &&
	    PERMMASK(statbuf.st_mode) != DB_DIR_PERM_UG) {
		syslog(LOG_ERR, "database directory %s has wrong permission bits 0%03o (they should be 0%03o or 0%03o)",
		    path, PERMMASK(statbuf.st_mode), DB_DIR_PERM_UG, DB_DIR_PERM_U);
		return -1;
	}
	if (PERMMASK(statbuf.st_mode) != rule->db_group.dir_mode) {
		syslog(LOG_WARNING, "database directory %s has incorrect permission bits 0%03o, fixing -> 0%03o",
		    path, PERMMASK(statbuf.st_mode), rule->db_group.dir_mode);
		if (fix_db_dir(path, rule) < 0)
			return -1;
	} else if (statbuf.st_gid != rule->db_group.group_id) {
		syslog(LOG_WARNING, "database directory %s has wrong group owner GID %d (it should be GID %ld), fixing...",
		    path, statbuf.st_gid, rule->db_group.group_id);
		if (fix_db_dir(path, rule) < 0)
			return -1;
	}
	return 1;
}

/*
 * Do recursive checking of database files and directories starting
 * from the start directory (all files and directories should belong
 * to the rule *rule).
 */
static int
check_db_files_recur(const char *start, const struct rule *rule)
{
	char		*path;
	DIR		*dp;
	struct stat	statbuf;
	struct dirent	*dirp;

	if ( (dp = opendir(start)) == NULL) {
		syslog(LOG_ERR, "opendir(%s): %m", start);
		return -1;
	}
	while ( (dirp = readdir(dp)) != 0) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
			continue;
		if (asprintf(&path, "%s/%s", start, dirp->d_name) < 0) {
			syslog(LOG_ERR, "asprintf: %m");
			return -1;
		}
		if (lstat(path, &statbuf) < 0) {
			syslog(LOG_ERR, "lstat(%s): %m", path);
			return -1;
		}
		if (S_ISREG(statbuf.st_mode)) {
			if (check_db_file(path, rule) < 0)
				return -1;
		} else if (S_ISDIR(statbuf.st_mode)) {
			if (check_db_dir(path, rule) < 0)
				return -1;
			if (check_db_files_recur(path, rule) < 0)
				return -1;
		} else {
			syslog(LOG_ERR, "%s must be a regular file or a directory", path);
			return -1;
		}
		free(path);
	}
	if (closedir(dp) < 0) {
		syslog(LOG_ERR, "closedir(%s): %m", start);
		return -1;
	}
	return 0;
}

/*
 * Check and fix (if needed) database files and directories group owners,
 * permission bits.
 */
static int
check_db_files(void)
{
	char		*path;
	DIR		*dp;
	struct stat	statbuf;
	struct dirent	*dirp;
	struct rule	*rule;

	if ( (dp = opendir(db_dir)) == NULL) {
		syslog(LOG_ERR, "opendir(%s): %m", db_dir);
		return -1;
	}
	while ( (dirp = readdir(dp)) != 0) {
		if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
			continue;
		/* check only that directories, for which we have 
		   appropriate "rule" sections in the configuration file */
		SLIST_FOREACH(rule, &rule_head, rule_entry)
			if (strcmp(dirp->d_name, rule->rulename) == 0) {
				if (asprintf(&path, "%s/%s", db_dir, dirp->d_name) < 0) {
					syslog(LOG_ERR, "asprintf: %m");
					return -1;
				}
				if (lstat(path, &statbuf) < 0) {
					syslog(LOG_ERR, "lstat(%s): %m", path);
					return -1;
				}
				if (!S_ISDIR(statbuf.st_mode)) {
					syslog(LOG_ERR, "%s is expected to be a directory", path);
					return -1;
				}
				if (statbuf.st_uid != 0) {
					syslog(LOG_ERR, "rule database directory %s has wrong owner UID %d (it should be owned by root)",
					    path, statbuf.st_uid);
					return -1;
				}
				if (PERMMASK(statbuf.st_mode) != DB_DIR_PERM_UG &&
				    PERMMASK(statbuf.st_mode) != DB_DIR_PERM_U) {
					syslog(LOG_ERR, "rule database directory %s has wrong permission bits 0%03o (they should be 0%03o or 0%03o)",
					    path, PERMMASK(statbuf.st_mode), DB_DIR_PERM_UG, DB_DIR_PERM_U);
					return -1;
				}
				if (PERMMASK(statbuf.st_mode) != rule->db_group.dir_mode) {
					syslog(LOG_WARNING, "rule database directory %s has incorrect permission bits 0%03o",
					    path, PERMMASK(statbuf.st_mode));
					syslog(LOG_WARNING, "checking all files and directories in the %s directory...", path);
					if (check_db_files_recur(path, rule) < 0)
						return -1;
					syslog(LOG_WARNING, "changing rule database directory %s permission bits to 0%03o",
					    path, rule->db_group.dir_mode);
					if (fix_db_dir(path, rule) < 0)
						return -1;
				} else if (statbuf.st_gid != rule->db_group.group_id) {
					syslog(LOG_WARNING, "rule database directory %s has wrong group owner GID %d",
						    path, statbuf.st_gid);
					syslog(LOG_WARNING, "checking all files and directories in the %s directory...", path);
					if (check_db_files_recur(path, rule) < 0)
						return -1;
					syslog(LOG_WARNING, "changing rule database directory %s group owner to GID %ld)",
					    path, rule->db_group.group_id);
					if (fix_db_dir(path, rule) < 0)
						return -1;
				}
				free(path);
				break;
			}
	}
	if (closedir(dp) < 0) {
		syslog(LOG_ERR, "closedir(%s): %m", db_dir);
		return -1;
	}
	return 0;
}

/*
 * Check main database directory: owner and permission bits.
 * If there is error/problem, then nothing is fixed.
 */
static int
check_main_db_dir(void)
{
	struct stat	statbuf;

	if (lstat(db_dir, &statbuf) < 0) {
		syslog(LOG_ERR, "lstat(%s): %m", db_dir);
		return -1;
	}
	if (!S_ISDIR(statbuf.st_mode)) {
		syslog(LOG_ERR, "%s is expected to be a directory", db_dir);
		return -1;
	}
	if (statbuf.st_uid != 0) {
		syslog(LOG_ERR, "main database directory %s has wrong owner UID %d (it should be owned by root)",
		    db_dir, statbuf.st_uid);

		/* FIX dir owner  	*/
	 if (chown(db_dir, 0, 0) < 0) {
                syslog(LOG_ERR, "chown(%s, 0, 0): %m", db_dir);
                return -1;
        	}

	/*	return -1;	*/
	}
	if (PERMMASK(statbuf.st_mode) != MAIN_DB_DIR_PERM) {
		syslog(LOG_ERR, "main database directory %s has wrong permission bits 0%03o (they should be 0%03o)",
		    db_dir, PERMMASK(statbuf.st_mode), MAIN_DB_DIR_PERM);

		/* FIX dir mode  	*/
 	 if (chmod(db_dir, MAIN_DB_DIR_PERM) < 0) {
                syslog(LOG_ERR, "chmod(%s, 0%03o): %m", db_dir, statbuf.st_mode & MAIN_DB_DIR_PERM);
                return -1;
		}	

	/*	return -1;	*/

	}
	return 0;
}

/*
 * Create a file in the database: set proper owner and permission bits.
 */
FILE *
create_db_file(const char *path, const struct rule *rule)
{
	int	fd;
	FILE	*fp;

	if ( (fd = open(path, O_RDWR|O_CREAT, rule->db_group.file_mode)) < 0) {
		syslog(LOG_ERR, "open(%s, O_RDWR|O_CREAT, 0%03o): %m", path, rule->db_group.file_mode);
		return NULL;
	}
	if (chown(path, 0, rule->db_group.group_id) < 0) {
		syslog(LOG_ERR, "chown(%s, 0, %ld): %m", path, rule->db_group.group_id);
		return NULL;
	}
	/* some file can be already exists, truncate it */
	if (ftruncate(fd, (off_t)0) < 0) {
		syslog(LOG_ERR, "ftruncate(%s, 0): %m", path);
		return NULL;
	}
	if ( (fp = fdopen(fd, "r+")) == NULL)
		syslog(LOG_ERR, "fdopen(%s, \"r+\"): %m", path);
	return fp;
}

/*
 * Create a directory in the database: set proper owner and permission bits.
 */
int
create_db_dir(const char *path, const struct rule *rule)
{
	if (mkdir(path, rule->db_group.dir_mode) < 0) {
		syslog(LOG_ERR, "mkdir(%s, 0%03o): %m", path, rule->db_group.dir_mode);
		return -1;
	}
	if (chown(path, 0, rule->db_group.group_id) < 0) {
		syslog(LOG_ERR, "chown(%s, 0, %ld): %m", path, rule->db_group.group_id);
		return -1;
	}
	return 0;
}

/*
 * Init accouting rules: create/check directories for rules,
 * create/overwrite info files, create/open limits.
 */
static int
init_db_rules(void)
{
	char		*path;
	FILE		*fp;
	struct rule	*rule;
	struct limit	*limit;
	struct stat	statbuf;

	SLIST_FOREACH(rule, &rule_head, rule_entry) {
		/* check directory for rule */
		if (asprintf(&path, "%s/%s", db_dir, rule->rulename) < 0) {
			syslog(LOG_ERR, "asprintf: %m");
			return -1;
		}
		if (lstat(path, &statbuf) < 0) {
			if (errno != ENOENT) {
				syslog(LOG_ERR, "lstat(%s): %m", path);
				return -1;
			}
			syslog(LOG_INFO, "creating rule directory %s", path);
			if (create_db_dir(path, rule) < 0)
				return -1;
		}
		free(path);

		/* check directory for limits */
		if (asprintf(&path, "%s/%s/" LIMITSDIR, db_dir, rule->rulename) < 0) {
			syslog(LOG_ERR, "asprintf: %m");
			return -1;
		}
		if (lstat(path, &statbuf) < 0) {
			if (errno != ENOENT) {
				syslog(LOG_ERR, "lstat(%s): %m", path);
				return -1;
			}
			if (create_db_dir(path, rule) < 0)
				return -1;
		}
		free(path);

		/* create/overwrite info file */
		if (asprintf(&path, "%s/%s/" INFOFILE, db_dir, rule->rulename) < 0) {
			syslog(LOG_ERR, "asprintf: %m");
			return -1;
		}
		if (rule->info != NULL) {
			if ( (fp = create_db_file(path, rule)) == NULL)
				return -1;
			if (fprintf(fp, "%s", rule->info) != strlen(rule->info)) {
				syslog(LOG_ERR, "fprintf(%s): %m", path);
				return -1;
			}
			if (fclose(fp) != 0) {
				syslog(LOG_ERR, "fclose(%s): %m", path);
				return -1;
			}
			free(rule->info);
			rule->info = NULL;
		} else {
			if (unlink(path) < 0)
				if (errno != ENOENT) {
					syslog(LOG_ERR, "unlink(%s): %m", path);
					return -1;
				}
		}
		free(path);

		/* create directories for limits */
		SLIST_FOREACH(limit, &rule->limit_head, limit_entry) {
			/* create directory for limit */
			if (asprintf(&path, "%s/%s/" LIMITSDIR "/%s", db_dir,
			    rule->rulename, limit->limitname) < 0) {
				syslog(LOG_ERR, "asprintf: %m");
				return -1;
			}
			if (lstat(path, &statbuf) < 0) {
				if (errno != ENOENT) {
					syslog(LOG_ERR, "lstat(%s): %m", path);
					return -1;
				}
				syslog(LOG_INFO, "creating directory for rule %s, limit %s",
				    rule->rulename, limit->limitname);
				if (create_db_dir(path, rule) < 0)
					return -1;
			}
			free(path);

			/* create or open file for limit accounting */
			if (asprintf(&path, "%s/%s/" LIMITSDIR "/%s/" LIMITFILE,
			    db_dir, rule->rulename, limit->limitname) < 0) {
				syslog(LOG_ERR, "asprintf: %m");
				return -1;
			}
			if (lstat(path, &statbuf) < 0) {
				if (errno != ENOENT) {
					syslog(LOG_ERR, "lstat(%s): %m", path);
					return -1;
				}
				if ( (limit->fp = create_db_file(path, rule)) == NULL)
					return -1;
			} else {
				if (statbuf.st_size == 0)
					syslog(LOG_WARNING, "file %s is empty, it will be fixed", path);
				if ( (limit->fp = fopen(path, "r+")) == NULL) {
					syslog(LOG_ERR, "fopen(%s, \"r+\"): %m", path);
					return -1;
				}
			}
			limit->fd = fileno(limit->fp);
			limit->filename = path;

			/* create info file for limit */
			if (asprintf(&path, "%s/%s/" LIMITSDIR "/%s/" INFOFILE,
			    db_dir, rule->rulename, limit->limitname) < 0) {
				syslog(LOG_ERR, "asprintf: %m");
				return -1;
			}
			if (limit->info != NULL) {
				if ( (fp = create_db_file(path, rule)) == NULL)
					return -1;
				if (fprintf(fp, "%s", limit->info) != strlen(limit->info)) {
					syslog(LOG_ERR, "fprintf(%s): %m", path);
					return -1;
				}
				if (fclose(fp) != 0) {
					syslog(LOG_ERR, "fclose(%s): %m", path);
					return -1;
				}
				free(limit->info);
				limit->info = NULL;
			} else {
				if (unlink(path) < 0)
					if (errno != ENOENT) {
						syslog(LOG_ERR, "unlink(%s): %m", path);
						return -1;
					}
			}
			free(path);
		}
	}
	return 0;
}

/*
 * Create "lock db" file if it does not exist and lock it.
 */
static int
check_lock_db_file(void)
{
	struct stat	statbuf;

	free(lock_db_file);
	if (asprintf(&lock_db_file, "%s/"LOCKDBFILE, db_dir) < 0) {
		syslog(LOG_ERR, "check_lock_db_file: asprintf: %m");
		return -1;
	}
	if (lstat(lock_db_file, &statbuf) < 0) {
		int	fd;

		if (errno != ENOENT) {
			syslog(LOG_ERR, "lstat(%s): %m", lock_db_file);
			return -1;
		}
		Umask(UMASK_RESTRICT);
		syslog(LOG_INFO, "creating database lock file %s", lock_db_file);
		if ( (fd = open(lock_db_file, O_WRONLY|O_CREAT, LOCK_DB_FILE_PERM)) < 0) {
			syslog(LOG_ERR, "open(%s, O_WRONLY|O_CREAT, 0%03o): %m", lock_db_file, LOCK_DB_FILE_PERM);
			return -1;
		}
		Umask(UMASK_DEF);
		if (close(fd) < 0) {
			syslog(LOG_ERR, "close(%s): %m", lock_db_file);
			return -1;
		}
	} else {
		if (statbuf.st_uid != 0) {
			syslog(LOG_ERR, "database lock file %s has wrong owner UID %d (it should be owned by root)",
			    lock_db_file, statbuf.st_uid);
			return -1;
		}
		if (!S_ISREG(statbuf.st_mode)) {
			syslog(LOG_ERR, "database lock file %s is expected to be a regular file", lock_db_file);
			return -1;
		}
		if (PERMMASK(statbuf.st_mode) != LOCK_DB_FILE_PERM) {
			syslog(LOG_ERR, "database lock file %s has wrong permission bits 0%03o (they should be 0%03o)",
			    lock_db_file, PERMMASK(statbuf.st_mode), LOCK_DB_FILE_PERM);

		if (chmod(lock_db_file, LOCK_DB_FILE_PERM) < 0) {
                		syslog(LOG_ERR, "chmod(%s, 0%03o): %m",
                       			 lock_db_file, statbuf.st_mode & LOCK_DB_FILE_PERM);
		                return -1;
		        }

	/*		return -1;	*/
		}
	}
	return 0;
}

/*
 * Check ownership and mode of files and directories in the database.
 * Init rules and limits.
 */
int
init_db(void)
{
	struct stat	statbuf;

	init_sig_alrm2();

	if (lstat(db_dir, &statbuf) < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "lstat(%s): %m", db_dir);
			return -1;
		}
		Umask(UMASK_RESTRICT);
		syslog(LOG_INFO, "creating main database directory %s", db_dir);
		if (mkdir(db_dir, MAIN_DB_DIR_PERM) < 0) {
			syslog(LOG_ERR, "mkdir(%s, 0%03o): %m", db_dir, MAIN_DB_DIR_PERM);
			return -1;
		}
		Umask(UMASK_DEF);
	} else if (check_main_db_dir() < 0)
		return -1;

	if (check_lock_db_file() < 0)
		return -1;

	if (lock_db && lock_whole_db_write() < 0) {
		syslog(LOG_ERR, "cannot lock whole database %s", db_dir);
		return -1;
	}

	if (check_db_files() < 0)
		return -1;

	if (init_db_rules() < 0)
		return -1;

	time(&curr_time);
	localtime_r(&curr_time, &curr_tm);
	curwday = curr_tm.tm_wday;

	if (init_limits(1) < 0)
		return -1;

	if (db_file_is_locked && unlock_whole_db() < 0) {
		syslog(LOG_ERR, "cannot unlock whole database %s", db_dir);
		return -1;
	}
	return 0;
}

/*
 * Build RE to check database correct values.
 */
int
build_db_regexes(void)
{
#define	REGCOMP(x)								\
	if ( (re_errcode = regcomp(&reg_ ## x, pat_ ## x, REG_EXTENDED|REG_NOSUB)) != 0) {\
		re_form_errbuf();						\
		syslog(LOG_ERR, "regcomp(" #x "): %s", re_errbuf);		\
		return -1;							\
	}

	REGCOMP(limit_line1);
	REGCOMP(limit_timestamp);
	return 0;
}
