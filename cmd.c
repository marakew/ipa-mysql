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
  "@(#)$Id: cmd.c,v 1.6.2.1 2003/07/08 08:30:01 simon Exp $";
#endif /* !lint */


#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "cmd.h"

#include "debug.h"
#include "ipa.h"


#ifdef __GNUC__
static void	fprintf_err(const char *, ...) __attribute__ ((format (printf, 1, 2)));
static void	exec_failed_log(u_int, const char *, va_list) __attribute__ ((format (printf, 2, 0)));
static int	exec_cmd(const struct cmd *, u_int, const char *, va_list) __attribute__ ((format (printf, 3, 0)));
static int	exec_cmd_perm(const struct cmd *, u_int, const char *, va_list) __attribute__ ((format (printf, 3, 0)));
#endif /* __GNUC__ */

/*
 * Send message to syslog about some problems with command.
 */
static void
exec_failed_log(u_int no, const char *message, va_list ap)
{
	vsyslog(LOG_ERR, message, ap);
	syslog(LOG_ERR, "  -> command in exec #%u failed", no + 1);
}

/*
 * Run command: pass command string to system(3).
 */
static int
exec_cmd(const struct cmd *cmdp, u_int no, const char *message, va_list ap)
{
	int	status;

	if (debug_exec > 0) {
		uid_t		uid;
		gid_t		gid;
		struct passwd	*passwdp;
		struct group	*groupp;

		uid = getuid();
		gid = getgid();
		passwdp = getpwuid(uid);
		groupp = getgrgid(gid);
		if (debug_exec == 1)
			syslog(LOG_INFO, "exec_cmd: exec #%u by %s:%s, UID %d GID %d",
			    no + 1, passwdp != NULL ? passwdp->pw_name : "(UNKNOWN USER)",
			    groupp != NULL ? groupp->gr_name : "(UNKNOWN GROUP)", myuid, mygid);
		else
			syslog(LOG_INFO, "exec_cmd: exec #%u (%s) by %s:%s, UID %d GID %d",
			    no + 1, cmdp->str, passwdp != NULL ? passwdp->pw_name : "(UNKNOWN USER)",
			    groupp != NULL ? groupp->gr_name : "(UNKNOWN GROUP)", myuid, mygid);
	}
	if ( (status = system(cmdp->str)) < 0)
		syslog(LOG_ERR, "exec_cmd: system: %m");
	else if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 127) {
			syslog(LOG_ERR, "exec_cmd: system: exit status = 127. Did the execution of the shell fail?");
			status = -1;
		}
	} else if (WIFSIGNALED(status)) {
		syslog(LOG_ERR, "exec_cmd: system: child abnormal termination, signal %d '%s'%s",
		    WTERMSIG(status), sys_signame[WTERMSIG(status)],
		    WCOREDUMP(status) ? " (core file generated)" : "");
		status = -1;
	} else if (WIFSTOPPED(status)) {
		syslog(LOG_ERR, "exec_cmd: system: child stopped, signal %d '%s'",
		    WSTOPSIG(status), sys_signame[WSTOPSIG(status)]);
		status = -1;
	}
	if (status < 0) {
		exec_failed_log(no, message, ap);
		return -1;
	}
	return 0;
}

/*
 * Fork(2) child, change UID, GID and supplementary GIDs if needed
 * and run command.
 */
static int
exec_cmd_perm(const struct cmd *cmdp, u_int no, const char *message, va_list ap)
{
	pid_t		childpid;

	if (!cmdp->uid_set) {
		/* Need to change only group. Don't need to fork() extra child */
		if (setgid(cmdp->gid) < 0) {
			syslog(LOG_ERR, "exec_cmd_perm: setgid(%lu): %m", cmdp->gid);
			exec_failed_log(no, message, ap);
			return -1;
		}
		exec_cmd(cmdp, no, message, ap);
		if (setgid(mygid) < 0) {
			syslog(LOG_ERR, "cannot change GID back, setgid(%u): %m", mygid);
			return -1;
		}
		return 0;
	}

	if ( (childpid = fork()) < 0) {
		syslog(LOG_ERR, "exec_cmd_perm: fork: %m");
		exec_failed_log(no, message, ap);
		return -1;
	}

	if (childpid == 0) {
		/* child */
		int		fd;
		struct rlimit	flim;

		getrlimit(RLIMIT_NOFILE, &flim);

		closelog();
		for (fd = 0; fd < flim.rlim_max; ++fd)
			if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO)
				close(fd);

		openlog(logfacil, logopt, LOG_USER);
		if (cmdp->suppl_gid != NULL) {
			/* exec(user:group) or exec(user) */
			if (setgroups(cmdp->nsuppl_gid, cmdp->suppl_gid) < 0) {
				syslog(LOG_ERR, "exec_cmd_perm: setgroups: %m");
				exec_failed_log(no, message, ap);
				closelog();
				exit(0);
			}
		}
		if (cmdp->gid_set) {
			if (setgid(cmdp->gid) < 0) {
				syslog(LOG_ERR, "exec_cmd_perm: setgid(%lu): %m", cmdp->gid);
				exec_failed_log(no, message, ap);
				closelog();
				exit(0);
			}
		}
		if (setuid(cmdp->uid) < 0) {
			syslog(LOG_ERR, "exec_cmd_perm: setuid(%lu): %m", cmdp->uid);
			exec_failed_log(no, message, ap);
			closelog();
			exit(0);
		}
		if (exec_cmd(cmdp, no, message, ap) < 0 || debug_exec > 0)
			closelog();
		exit(0);
	} else {
		/* parent */
		int	status;

		while (waitpid(childpid, &status, WUNTRACED) < 0)
			if (errno != EINTR) {
				syslog(LOG_ERR, "exec_cmd_perm: waitpid(PID %u): %m", childpid);
				return -1;
			}

		if (WIFSIGNALED(status)) {
			syslog(LOG_ERR, "exec_cmd_perm: child abnormal termination, signal %d '%s'%s",
			    WTERMSIG(status), sys_signame[WTERMSIG(status)],
			    WCOREDUMP(status) ? " (core file generated)" : "");
			return -1;
		}
		if (WIFSTOPPED(status)) {
			syslog(LOG_ERR, "exec_cmd_perm: child stopped, signal %d '%s'",
			    WSTOPSIG(status), sys_signame[WSTOPSIG(status)]);
			return -1;
		}
		return 0; 
	}
	/* NOTREACHED */
}

/*
 * Run command list in background and wait for their execution.
 */
int
exec_cmd_list(const struct cmd *cmdp, u_int n, const char *message, ...)
{
	pid_t		childpid;

	if ( (childpid = fork()) < 0) {
		syslog(LOG_ERR, "exec_cmd_list: fork: %m");
		return -1;
	}

	if (childpid == 0) {
		/* child */
		int		fd, fl = 0, ret = 0;
		u_int		i;
		va_list		ap;
		struct rlimit	flim;

		getrlimit(RLIMIT_NOFILE, &flim);

		closelog();
		for (fd = 0; fd < flim.rlim_max; ++fd)
			if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO)
				close(fd);

		openlog(logfacil, logopt, LOG_USER);

		va_start(ap, message);
		for (i = 0; i < n; ++cmdp, ++i) {
			if (cmdp->uid_set || cmdp->gid_set)
				ret += exec_cmd_perm(cmdp, i, message, ap);
			else {
				ret += exec_cmd(cmdp, i, message, ap);
				fl = 1;
			}
		}
		va_end(ap);
		if (ret < 0 || (fl == 1 && debug_exec > 0))
			closelog();
		exit(0);
	} else {
		/* parent */
		int	status;

		while (waitpid(childpid, &status, WUNTRACED) < 0)
			if (errno != EINTR) {
				syslog(LOG_ERR, "exec_cmd_list: waitpid(PID %u): %m", childpid);
				return 0;
			}

		if (WIFSIGNALED(status))
			syslog(LOG_ERR, "exec_cmd_list: child abnormal termination, signal %d '%s'%s",
			    WTERMSIG(status), sys_signame[WTERMSIG(status)],
			    WCOREDUMP(status) ? " (core file generated)" : "");
		else if (WIFSTOPPED(status))
			syslog(LOG_ERR, "exec_cmd_list: child stopped, signal %d '%s'",
			    WSTOPSIG(status), sys_signame[WSTOPSIG(status)]);
		return 0;
	}
	/* NOTREACHED */
}

/*
 * Run command list in background.
 */
pid_t
exec_cmd_list_bg(const struct cmd *cmdp, u_int n, const char *message, ...)
{
	u_int		i;
	int		fd, ret = 0, fl = 0;
	pid_t		childpid;
	va_list		ap;
	struct rlimit	flim;

	if ( (childpid = fork()) < 0) {
		syslog(LOG_ERR, "fork: %m");
		return -1;
	}
	if (childpid != 0)
		/* parent */
		return childpid;

	/* child */
	getrlimit(RLIMIT_NOFILE, &flim);
	closelog();
	for (fd = 0; fd < flim.rlim_max; ++fd)
		if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO)
			close(fd);

	openlog(logfacil, logopt, LOG_USER);
	va_start(ap, message);
	for (i = 0; i < n; ++cmdp, ++i) {
		if (cmdp->uid_set || cmdp->gid_set)
			ret += exec_cmd_perm(cmdp, i, message, ap);
		else {
			ret += exec_cmd(cmdp, i, message, ap);
			fl = 1;
		}
	}
	va_end(ap);
	if (ret < 0 || (fl == 1 && debug_exec > 0))
		closelog();
	exit(0);
	/* NOTREACHED */
}

/*
 * Release memory used by command list.
 */
void
free_cmd_list(struct cmd *cmd_head, u_int n)
{
	struct cmd	*cmdp;
	u_int		i;

	if (cmd_head) {
		for (cmdp = cmd_head, i = 0; i < n; ++cmdp, ++i) {
			free(cmdp->str);
			free(cmdp->suppl_gid);
		}
		free(cmd_head);
	}
}

/*
 * Release memory used by commands structure.
 */
void
free_commands(struct commands *commandsp)
{
	free_cmd_list(commandsp->cmd, commandsp->ncmd);
	free_cmd_list(commandsp->cmd_if_limit, commandsp->ncmd_if_limit);
	free_cmd_list(commandsp->cmd_if_nolimit, commandsp->ncmd_if_nolimit);
}

/*
 * Output message to stderr and error message if errno > 0.
 */
static void
fprintf_err(const char *message, ...)
{
	int	errno_save = errno;
	va_list	ap;

	va_start(ap, message);
	fflush(stdout);
	fprintf(stderr, "    - Error: ");
	vfprintf(stderr, message, ap);
	if (errno_save > 0)
		fprintf(stderr, ": %s\n", strerror(errno_save));
	else
		fprintf(stderr, "\n");
	va_end(ap);
}


/*
 * Run command: pass command string to system(3), output all
 * messages to console.
 */
static void
exec_cmd_cons(const struct cmd *cmdp)
{
	int	status;

	if ( (status = system(cmdp->str)) < 0) {
		fprintf_err("system");
		return;
	}
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 127) {
			fprintf_err("system: exit status = 127. Did the execution of the shell fail?");
			return;
		}
	} else if (WIFSIGNALED(status)) {
		fprintf_err("system: child abnormal termination, signal %d '%s'%s",
		    WTERMSIG(status), sys_signame[WTERMSIG(status)],
		    WCOREDUMP(status) ? " (core file generated)" : "");
		return;
	} else if (WIFSTOPPED(status)) {
		fprintf_err("system: child stopped, signal %d '%s'",
		    WSTOPSIG(status), sys_signame[WSTOPSIG(status)]);
		return;
	}
}

/*
 * Fork() child, change UID, GID and supplementary GIDs if needed
 * and run command, but output all messages to console.
 */
static int
exec_cmd_perm_cons(const struct cmd *cmdp)
{
	pid_t		childpid;

	if (!cmdp->uid_set) {
		/* Need to change only group. Don't need to fork() extra child */
		if (setgid(cmdp->gid) < 0) {
			fprintf_err("setgid(%lu)", cmdp->gid);
			return -1;
		}
		exec_cmd_cons(cmdp);
		if (setgid(mygid) < 0) {
			fprintf_err("cannot change GID back, setgid(%u)", mygid);
			return -1; 
		}
		return 0;
	}

	if ( (childpid = fork()) < 0) {
		fprintf_err("fork");
		return 0;
	}

	if (childpid == 0) {
		/* child */

		if (cmdp->suppl_gid != NULL) {
			/* exec(user:group) or exec(user) */
			if (setgroups(cmdp->nsuppl_gid, cmdp->suppl_gid) < 0) {
				fprintf_err("setgroups");
				exit(0);
			}
		}
		if (cmdp->gid_set) {
			if (setgid(cmdp->gid) < 0) {
				fprintf_err("setgid(%lu)", cmdp->gid);
				exit(0);
			}
		}
		if (setuid(cmdp->uid) < 0) {
			fprintf_err("setuid(%lu)", cmdp->uid);
			exit(0);
		}
		exec_cmd_cons(cmdp);
		exit(0);
	} else {
		/* parent */
		int	status;

		while (waitpid(childpid, &status, WUNTRACED) < 0)
			if (errno != EINTR) {
				syslog(LOG_ERR, "waitpid(PID %u)", childpid);
				return 0;
			}

		if (WIFSIGNALED(status))
			fprintf_err("child abnormal termination, signal %d '%s'%s",
			    WTERMSIG(status), sys_signame[WTERMSIG(status)],
			    WCOREDUMP(status) ? " (core file generated)" : "");
		else if (WIFSTOPPED(status))
			fprintf_err("child stopped, signal %d '%s'",
			    WSTOPSIG(status), sys_signame[WSTOPSIG(status)]);
		return 0; 
	}
	/* NOTREACHED */
}

/*
 * Run commands from given options in the command line.
 */
int
run_opt_command(const struct commands *commandsp, u_int cmd_code)
{
	u_int		nbrace = 0, ncmd, i;
	struct passwd	*passwdp;
	struct group	*groupp;
	struct cmd	*cmd_head, *cmdp;

	printf("Run commands from section:\n");
	if (opt_rule != NULL) {
		printf(" rule %s {", opt_rule);
		++nbrace;
		if (opt_limit != NULL) {
			printf(" limit %s {", opt_limit);
			++nbrace;
		}
	}
	if (cmd_code & CMD_STARTUP)
		printf(" startup {");
	else if (cmd_code & CMD_SHUTDOWN)
		printf(" shutdown {");
	else if (cmd_code & CMD_EXPIRE)
		printf(" expire {");
	else /* cmd_code & CMD_REACH */
		printf(" reach {");
	cmd_head = commandsp->cmd;
	ncmd = commandsp->ncmd;
	++nbrace;
	if (cmd_code & CMD_IF_LIMIT) {
		printf(" if_limit_is_reached {");
		cmd_head = commandsp->cmd_if_limit;
		ncmd = commandsp->ncmd_if_limit;
		++nbrace;
	} else if (cmd_code & CMD_IF_NOLIMIT) {
		printf(" if_limit_is_not_reached {");
		++nbrace;
		cmd_head = commandsp->cmd_if_nolimit;
		ncmd = commandsp->ncmd_if_nolimit;
	}
	while (nbrace--)
		printf("}");
	printf("\n");
	if (cmd_head == NULL)
		printf("  - nothing to run\n");
	else {
		for (i = 0, cmdp = cmd_head; i < ncmd; ++cmdp, ++i) {
			if (cmdp->uid_set)
				passwdp = getpwuid(cmdp->uid);
			else {
				passwdp = getpwuid(myuid);
				cmdp->uid = myuid;
			}
			if (cmdp->gid_set)
				groupp = getgrgid(cmdp->gid);
			else {
				groupp = getgrgid(mygid);
				cmdp->gid = mygid;
			}

			printf("  * exec(");
			if (passwdp != NULL)
				printf("%s:", passwdp->pw_name);
			else
				printf("%lu:", cmdp->uid);
			if (groupp != NULL)
				printf("%s", groupp->gr_name);
			else
				printf("%lu", cmdp->gid);
			printf(") = %s\n", cmdp->str);
			fflush(stdout);

			if (cmdp->uid_set || cmdp->gid_set) {
				if (exec_cmd_perm_cons(cmdp) < 0)
					return -1;
			} else
				exec_cmd_cons(cmdp);
		}
	}
	return 0;
}
