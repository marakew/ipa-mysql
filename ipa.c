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
  "@(#)$Id: ipa.c,v 1.6.2.9 2003/11/11 10:23:42 simon Exp $";
#endif /* !lint */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <paths.h>
#ifdef _PATH_DEVNULL
static char *path_devnull = _PATH_DEVNULL;
#else
static char *path_devnull = "/dev/null";
#endif

#include "ipa.h"
#include "cmd.h"
#include "common.h"
#include "config.h"
#include "db.h"
#include "path.h"
#include "rules.h"

/*
 * This file is compiled first, check if we have at least one
 * accounting system support.
 */
#if !defined(WITH_IPFW) && !defined(WITH_IP6FW) && !defined(WITH_IPFIL) && !defined(WITH_PF)
# error You should enable at least one accounting system support.
#endif

#define IPA_MSG		"IPA"

uid_t		myuid;
gid_t		mygid;
int		debug = 0;	/* 1 if switch -d was used */
int		testconfig = 0; /* >0 if switch -t was used */

char		*opt_rule = NULL,
		*opt_limit = NULL;

int		logopt;
char		*logfacil = IPA_IDENT;

static char	*envprogname;
static int	pidfd;
static char	*pidfilename = PIDFILE;


static const char ipa_ident[] = IPA_IDENT;
static const char ipa_msg[] = IPA_MSG;

static void	show_usage(void), show_version(int);
static int	bg_init(void);
static int	lock_pidfile(void);
static int	set_sighandlers(int);
static int	parse_and_run_opt_command(int, char **);

#ifdef __GNUC__
static void	err_exit(const char *, ...) __attribute__ ((noreturn, format (printf, 1, 2)));
static void	errx_exit(const char *, ...) __attribute__ ((noreturn, format (printf, 1, 2)));
static void	abnormalterm(void) __attribute__ ((noreturn));
static void	runcopy_kill(int) __attribute__ ((noreturn));
#else
static void	err_exit(const char *, ...);
static void	errx_exit(const char *, ...);
static void	abnormalterm(void);
static void	runcopy_kill(int);
#endif

static void
remove_pid_file()
{
	if (close(pidfd) < 0)
		syslog(LOG_ERR, "close(%s): %m", pidfilename);
	if (unlink(pidfilename) < 0)
		syslog(LOG_ERR, "unlink(%s): %m", pidfilename);
}

int
main(int argc, char *argv[])
{
	int	opt;

	envprogname = argv[0];	/* save program name */
	opterr = 0;		/* don't allow getopt() to print own messages */
	umask(UMASK_DEF);

	while ( (opt = getopt(argc, argv, "dtvVhf:k:p:L:l:r:c:")) != -1)
		switch (opt) {
		case 'd':
			debug = 1;
			break;
		case 't':
			++testconfig;
			break;
		case 'f':
			cfgfilename_main = optarg;
			break;
		case 'k':
			if (strcmp(optarg, "shutdown") == 0)
				runcopy_kill(SIGTERM);
			if (strcmp(optarg, "kill") == 0)
				runcopy_kill(SIGKILL);
			if (strcmp(optarg, "reconfigure") == 0)
				runcopy_kill(SIGHUP);
			if (strcmp(optarg, "dump") == 0)
				runcopy_kill(SIGUSR1);
			errx_exit("invalid argument \"%s\" for switch -k", optarg);
			/* NOTREACHED */
		case 'p':
			pidfilename = optarg;
			if (*pidfilename != '/')
				errx_exit("path in the -p option should be absolute");
			break;
		case 'r':
			opt_rule = optarg;
			break;
		case 'l':
			opt_limit = optarg;
			break;
		case 'L':
			logfacil = optarg;
			break;
		case 'c':
			if (*optarg != '/')
				errx_exit("path in the -c option should be absolute");
			if (chroot(optarg) < 0)
				err_exit("chroot(%s)", optarg);
			break;
		case 'v':
			show_version(0);
			return 0;
		case 'V':
			show_version(1);
			return 0;
		case 'h':
			show_usage();
			return 0;
		case '?':
			errx_exit("invalid switch -%c", optopt);
			/* NOTREACHED */
		default:
			err_exit("getopt");
		}

	if (opt_limit != NULL && opt_rule == NULL)
		errx_exit("the -l option should be used with the -r option");
	if (opt_rule != NULL && optind == argc)
		errx_exit("cannot find a section name in the command line");

	if (testconfig) {
		if (optind < argc)
			errx_exit("non-switch argument \"%s\"", argv[optind]);
		if (parse_config(TEST_PARSING) < 0)
			return 1;
		show_config();
		return 0;
	}

	myuid = getuid();
	mygid = getgid();

	if (myuid != 0)
		errx_exit("ipa(8) can be run only by the super-user");

	if (optind < argc) {
		if (parse_config(CMD_PARSING) < 0)
			return 1;
		return parse_and_run_opt_command(argc, argv) < 0 ? 1 : 0;
	}

	if (lock_pidfile() < 0)
		return 1;

	logopt = LOG_PID|(debug ? LOG_PERROR : LOG_CONS);
	openlog(logfacil, logopt, LOG_USER);
	if (!debug) {
		if (bg_init() < 0) {
			syslog(LOG_ERR, "cannot run in the background");
			abnormalterm();
		}
		if (lock_pidfile() < 0)
			abnormalterm();
	}

	syslog(LOG_INFO, "------------------------------------------------");
	syslog(LOG_INFO, "%s: version %s started by UID %d GID %d",
	    ipa_msg, Version, myuid, mygid);
	Umask(UMASK_DEF);
	if (parse_config(STARTUP_PARSING) < 0)
		abnormalterm();

	if (build_db_regexes() < 0)
		abnormalterm();
	if (init_db() < 0)
		abnormalterm();

#ifdef WITH_IPFW
	if (use_ipfw)
		if (kipfw_init() < 0)
			abnormalterm();
#endif /* WITH_IPFW */

#ifdef WITH_IP6FW
	if (use_ip6fw)
		if (kip6fw_init() < 0)
			abnormalterm();
#endif /* WITH_IP6FW */

#ifdef WITH_IPFIL
 	if (use_ipfil)
		if (kipfil_init() < 0)
			abnormalterm();
#endif /* WITH_IPFIL */

#ifdef WITH_PF
	if (use_pf)
		if (kpf_init() < 0)
			abnormalterm();
#endif /* WITH_PF */

	if (set_sighandlers(0) < 0)
		abnormalterm();

	/* Startup */
	if (startup_global.cmd != NULL) {
		syslog(LOG_INFO, "run startup(global) commands...");
		if (exec_cmd_list(startup_global.cmd, startup_global.ncmd, "startup(global)") < 0)
			abnormalterm();
		free_cmd_list(startup_global.cmd, startup_global.ncmd);
	}
	if (run_rules_rc(0) < 0)
		abnormalterm();

	if (set_sighandlers(1) < 0) /* set SIGCHLD handler */
		abnormalterm();

	/* Working... */
	if (run_ipac() < 0) {
		syslog(LOG_ERR, "cannot make IP accounting");
		abnormalterm();
	}

	if (set_sighandlers(2) < 0) /* set SIGCHLD handler */
		abnormalterm();

	/* Shutdown */
	if (run_rules_rc(1) < 0)
		abnormalterm();
	if (shutdown_global.cmd != NULL) {
		syslog(LOG_INFO, "run shutdown(global) commands...");
		if (exec_cmd_list(shutdown_global.cmd, shutdown_global.ncmd, "shutdown(global)") < 0)
			abnormalterm();
	}

	remove_pid_file();
	syslog(LOG_INFO, "%s: version %s stopped", ipa_msg, Version);
	closelog();
	return 0;
}

/*
 * Output program name, message, error message and exit.
 */
static void
err_exit(const char *message, ...)
{
	int	errno_save = errno;
	va_list	ap;

	va_start(ap, message);
	fflush(stdout);
	fprintf(stderr, "%s: ", envprogname);
	vfprintf(stderr, message, ap);
	if (errno_save > 0)
		fprintf(stderr, ": %s\n", strerror(errno_save));
	else
		fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

/*
 * Output program name, message and exit.
 */
static void
errx_exit(const char *message, ...)
{
	va_list	ap;

	va_start(ap, message);
	fflush(stdout);
	fprintf(stderr, "%s: ", envprogname);
	vfprintf(stderr, message, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

/*
 * Run in the background: ignore signals TTOU, TTIN and TSTP,
 * fork() new process, chdir() to /, close() all available descriptors.
 * Open /dev/null and dup2() descriptors STDIN_FILENO, STDOUT_FILENO and
 * STDERR_FILENO to it.
 */
static int
bg_init(void)
{
	pid_t		childpid;
	int		fd;
	struct rlimit	flim;

	if (signal(SIGTTOU, SIG_IGN) == SIG_ERR) {
		syslog(LOG_ERR, "signal(SIGTTOU): %m");
		return -1;
	}
	if (signal(SIGTTIN, SIG_IGN) == SIG_ERR) {
		syslog(LOG_ERR, "signal(SIGTTIN): %m");
		return -1;
	}
	if (signal(SIGTSTP, SIG_IGN) == SIG_ERR) {
		syslog(LOG_ERR, "signal(SIGTSTP): %m");
		return -1;
	}

	if ( (childpid = fork()) < 0) {
		syslog(LOG_ERR, "fork: %m");
		return -1;
	}
	if (childpid != 0)
		_exit(0);	/* parent goes */
	/* child continues */
	setsid();
	chdir("/");
	getrlimit(RLIMIT_NOFILE, &flim);
	for (fd = 0; fd < flim.rlim_max; ++fd)
		if (fd != pidfd)
			close(fd);

	if ( (fd = open(path_devnull, O_RDWR)) < 0) {
		syslog(LOG_ERR, "open(%s): %m", path_devnull);
		return -1;
	}
	if (dup2(fd, STDIN_FILENO) < 0) { /* stdin -> /dev/null */
		syslog(LOG_ERR, "dup2(%d, %d): %m", fd, STDIN_FILENO);
		return -1;
	}
	if (dup2(fd, STDOUT_FILENO) < 0) { /* stdout -> /dev/null */
		syslog(LOG_ERR, "dup2(%d, %d): %m", fd, STDOUT_FILENO);
		return -1;
	}
	if (dup2(fd, STDERR_FILENO) < 0) { /* stderr -> /dev/null */
		syslog(LOG_ERR, "dup2(%d, %d): %m", fd, STDERR_FILENO);
		return -1;
	}
	if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO) {
		if (close(fd) < 0) {
			syslog(LOG_ERR, "close(FD %d): %m", fd);
			return -1;
		}
	}

	return 0;
}

/*
 * Lock file pidfilename to prevent multiple copies of itself from running
 * and stores its PID in this file.
 *
 * This function should be called twise: first call locks file pidfilename
 * and stores PID, second call just stores PID (it's necessary,
 * because bg_init() fork() new process).
 */
static int
lock_pidfile(void)
{
	int		val;
	static FILE	*fp = NULL;

	if (fp == NULL) {
		/* first call, don't use syslog */
		if ( (pidfd = open(pidfilename, O_RDWR|O_CREAT, 0644)) < 0 ||
		     (fp = fdopen(pidfd, "r+")) == NULL)
			err_exit("cannot open or create PID file %s", pidfilename);
		if (flock(pidfd, LOCK_EX|LOCK_NB) < 0) {
			int	errno_save = errno, other_pid;

			if (errno != EWOULDBLOCK)
				err_exit("flock(%s)", pidfilename);
			if (fscanf(fp, "%d", &other_pid) != 1) {
				errno = errno_save;
				err_exit("cannot lock file %s", pidfilename);
			} else {
				errno = errno_save;
				err_exit("cannot lock file %s, it may be locked by PID %d", pidfilename, other_pid);
			}
			return -1;
		}
		if ( (val = fcntl(pidfd, F_GETFD, 0)) < 0)
			err_exit("fcntl(%s, F_GETFD)", pidfilename);
		val |= FD_CLOEXEC;
		if (fcntl(pidfd, F_SETFD, val) < 0)
			err_exit("fcntl(%s, F_SETFD)", pidfilename);
		if (fseek(fp, 0L, SEEK_SET) < 0)
			err_exit("fseek(%s, 0, SEEK_SET)", pidfilename);
		if (fprintf(fp, "%d\n", getpid()) < 0)
			err_exit("fprintf(%s)", pidfilename);
		if (fflush(fp) != 0)
			err_exit("fflush(%s)", pidfilename);
		if (ftruncate(pidfd, ftell(fp)) < 0)
			err_exit("ftruncate(%s)", pidfilename);
	} else {
		/* next call, use syslog */
		if (fseek(fp, 0L, SEEK_SET) < 0) {
			syslog(LOG_ERR, "fseek(%s, 0, SEEK_SET): %m", pidfilename);
			return -1;
		}
		if (fprintf(fp, "%d\n", getpid()) < 0) {
			syslog(LOG_ERR, "fprintf(%s): %m", pidfilename);
			return -1;
		}
		if (fflush(fp) != 0) {
			syslog(LOG_ERR, "fflush(%s): %m", pidfilename);
			return -1;
		}
		if (ftruncate(pidfd, ftell(fp)) < 0) {
			syslog(LOG_ERR, "ftruncate(%s): %m", pidfilename);
			return -1;
		}
	}
	return 0;
}

/*
 * Set handlers for signals HUP, ALRM, CHLD, TERM and INT (if -d switch
 * was specified in command line and IPA is run as foreground
 * process).
 */
static int
set_sighandlers(int phase)
{
	struct sigaction	act;

	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	if (debug)
		sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGHUP);
	sigaddset(&act.sa_mask, SIGTERM);
	sigaddset(&act.sa_mask, SIGALRM);
	sigaddset(&act.sa_mask, SIGCHLD);
	sigaddset(&act.sa_mask, SIGUSR1);

	switch (phase) {
	case 0:
		act.sa_handler = end_work;
		if (debug) {
			if (sigaction(SIGINT, &act, (struct sigaction *)NULL) < 0) {
				syslog(LOG_ERR, "sigaction(SIGINT): %m");
				return -1;
			}
		}
		if (sigaction(SIGTERM, &act, (struct sigaction *)NULL) < 0) {
			syslog(LOG_ERR, "sigaction(SIGTERM): %m");
			return -1;
		}

		act.sa_handler = reconfigure;
		if (sigaction(SIGHUP, &act, (struct sigaction *)NULL) < 0) {
			syslog(LOG_ERR, "sigaction(SIGHUP): %m");
			return -1;
		}

		act.sa_handler = force_db_dump;
		if (sigaction(SIGUSR1, &act, (struct sigaction *)NULL) < 0) {
			syslog(LOG_ERR, "sigaction(SIGUSR1): %m");
			return -1;
		}

		act.sa_handler = sig_alrm;
		if (sigaction(SIGALRM, &act, (struct sigaction *)NULL) < 0) {
			syslog(LOG_ERR, "sigaction(SIGALRM): %m");
			return -1;
		}

		break;
	case 1:
		act.sa_handler = sig_chld;
		if (sigaction(SIGCHLD, &act, (struct sigaction *)NULL) < 0) {
			syslog(LOG_ERR, "sigaction(SIGCHLD): %m");
			return -1;
		}
		break;
	case 2:
		if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
			syslog(LOG_ERR, "signal(SIGCHLD, SIG_DFL): %m");
			return -1;
		}
		break;
	default:
		syslog(LOG_ERR, "set_sighandlers: unknown phase number %d", phase);
		return -1;
	}
	return 0;
}

/*
 * Send signal signo to the running copy of IPA. PID of the running copy is
 * taken from the file pidfilename.
 *
 * Check if the file pidfilename is really locked and if it is true, then send
 * a signal to PID stored in the file.
 */
static void
runcopy_kill(int signo)
{
	FILE		*fp;
	int		pid;
	struct flock	lock;

	if ( (fp = fopen(pidfilename, "r")) == NULL)
		err_exit("fopen(%s)", pidfilename);

	lock.l_start = 0;	/* from the beginning of the file */
	lock.l_len = 0;		/* entire file */
	lock.l_type = F_WRLCK;	/* write lock */
	lock.l_whence = SEEK_SET;
	if (fcntl(fileno(fp), F_GETLK, &lock) < 0)
		err_exit("fcntl(F_GETLK, %s)", pidfilename);
	if (lock.l_type == F_UNLCK)
		errx_exit("file %s is not locked, do not send any signals", pidfilename);

	if (fscanf(fp, "%d", &pid) != 1)
		err_exit("fscanf(%s, %%d): failed", pidfilename);

	printf("Sending signal %d '%s' to PID %d...", signo, sys_signame[signo], pid);

	if (kill(pid, signo) < 0) {
		printf("\n");
		fflush(stdout);
		err_exit("kill(PID %d, %d '%s')", pid, signo, sys_signame[signo]);
	}
	printf(" done\n");
	exit(0);
}

/*
 * Serious errors occured, log message and exit().
 */
static void
abnormalterm(void)
{
	remove_pid_file();
	syslog(LOG_ERR, "abnormal termination");
	exit(1);
}

/*
 * Output version number (-v and -h switch).
 */
static void
show_version(int detail)
{
	printf("%s, version %s (%s)\n", ipa_msg, Version, System);
	if (detail) {
		printf("Compiled on:\n   o "__DATE__", "__TIME__"\n");
#if defined(WITHOUT_IPFW) || defined(WITHOUT_IP6FW) || defined(WITHOUT_IPFIL) || defined(WITHOUT_PF) || defined(WITH_IP6FW_OPT)
	printf("Compile options:\n");
# ifdef WITHOUT_IPFW
	printf("   -DWITHOUT_IPFW\n");
# endif
# ifdef WITHOUT_IP6FW
	printf("   -DWITHOUT_IP6FW\n");
# endif
# ifdef WITHOUT_IPFIL
	printf("   -DWITHOUT_IPFIL\n");
# endif
# ifdef WITHOUT_PF
	printf("   -DWITHOUT_PF\n");
# endif
# ifdef WITH_IP6FW_OPT
	printf("   -DWITH_IP6FW\n");
# endif
#endif
		printf("Support:\n");
#ifdef WITH_IPFW
# ifdef IPFW2
		printf("   o IPv4 Firewall (IPFW2)\n");
# else
		printf("   o IPv4 Firewall\n");
# endif
#endif /* WITH_IPFW */
#ifdef WITH_IP6FW
		printf("   o IPv6 Firewall\n");
#endif
#ifdef WITH_IPFIL
		printf("   o IP Filter v"IPF_VERSION_STR"\n");
#endif
#ifdef WITH_PF
		printf("   o Packet Filter\n");
#endif
	}
}

/*
 * Output help message (-h switch).
 */
static void
show_usage(void)
{
	char	*prog;

	if ( (prog = strrchr(envprogname, '/')) != NULL)
		++prog;
	else
		prog = envprogname;

	show_version(0);
	printf("\
Usage: %s [-dhtVv] [-c <directory>] [-f <config-file>] [-p <pid-file>]\n\
	   [-k <signal>] [-L <log-facility>]\n\
       %s [-c <directory>] [-f <config-file>]\n\
           [-r <rule> [-l <limit>]] section [subsection]\n\
   -c <directory>\n\
   \tSpecifies the <directory> ipa(8) should chroot(2) into immediately\n\
   -d\tDo not run in the background, write all messages to stderr\n\
   \tas well to the syslog(8)\n\
   -f <config-file>\n\
   \tUse given <config-file> instead of using default configuration\n\
   \tfile %s\n\
   -h\tOutput this help message\n\
   -k <signal>\n\
   \tSend <signal> to running copy:\n\
   \t* dump - send signal USR1 (dump values of counters to database)\n\
   \t* kill - send signal KILL (running copy will be terminated by system)\n\
   \t* reconfigure - send signal HUP (cause rereading configuration file)\n\
   \t* shutdown - send signal TERM (cause shutdowning)\n\
   -L <log-facility>\n\
   \tUse given syslog <log-facility> instead of using default \"%s\"\n\
   -p <pid-file>\n\
   \tUse given <pid-file> instead of using default PID file %s\n\
   -r <rule> [-l <limit>]\n\
   \tSpecifies <rule> (and <limit>) from where following section\n\
   \t(and subsection) should be taken\n\
   -t\tParse configuration file, output its content and exit. If two -tt\n\
   \tswitches are used, then ipa(8) includes all configuration files from\n\
   \t\"include\" section(s) and checks them as one configuration file\n\
   -V\tShow information about ipa(8) and supported features\n\
   -v\tShow version number and exit\n\
   section [subsection]\n\
   \tRun commands from the given section: \"startup\", \"shutdown\" (subsection\n\
   \tcan be \"if_limit_is_reached\" or \"if_limit_is_not_reached\"),\n\
   \t\"reach\" or \"expire\"\n", prog, prog, CFGFILE, ipa_ident, PIDFILE);
}

/*
 * Determine section and subsection names,
 * run commands from the appropriate section.
 */
static int
parse_and_run_opt_command(int argc, char *argv[])
{
	char		*section;
	u_int		cmd_code = 0;
	struct rule	*rule;
	struct limit	*limit = NULL; /* initial value isn't used */
	struct commands	*commandsp;
	struct commands	commands_tmp;

	section = argv[optind];
	if (strcmp(section, "startup") == 0)
		cmd_code = CMD_STARTUP;
	else if (strcmp(section, "shutdown") == 0)
		cmd_code = CMD_SHUTDOWN;
	else if (strcmp(section, "reach") == 0)
		cmd_code = CMD_REACH;
	else if (strcmp(section, "expire") == 0)
		cmd_code = CMD_EXPIRE;
	else
		errx_exit("unknown or unexpected section \"%s\"", section);

	if (++optind < argc) {
		if ((opt_rule == NULL && opt_limit == NULL) ||
		    ((opt_rule != NULL && opt_limit != NULL) && (cmd_code == CMD_EXPIRE || cmd_code == CMD_REACH)))
			errx_exit("do not use more than one section name in this case");
		section = argv[optind];
		if (strcmp(section, "if_limit") == 0 ||
		    strcmp(section, "if_limit_reached") == 0 ||
		    strcmp(section, "if_limit_is_reached") == 0)
			cmd_code |= CMD_IF_LIMIT;
		else if (strcmp(section, "if_nolimit") == 0 ||
		    strcmp(section, "if_limit_not_reached") == 0 ||
		    strcmp(section, "if_limit_is_not_reached") == 0)
			cmd_code |= CMD_IF_NOLIMIT;
		else
			errx_exit("unknown subsection \"%s\"", section);
		if (++optind < argc)
			errx_exit("too many sections: \"%s\"", argv[optind]);
	}
	if (((cmd_code & CMD_REACH) || (cmd_code & CMD_EXPIRE)) && opt_limit == NULL)
		errx_exit("\"expire\" and \"reach\" sections names can be used only with a limit");
	if (opt_rule == NULL && opt_limit == NULL)
		commandsp = cmd_code & CMD_STARTUP ? &startup_global : &shutdown_global;
	else {
		SLIST_FOREACH(rule, &rule_head, rule_entry) {
			if (strcmp(rule->rulename, opt_rule) == 0) {
				if (opt_limit != NULL) {
					SLIST_FOREACH(limit, &rule->limit_head, limit_entry)
						if (strcmp(limit->limitname, opt_limit) == 0)
							break;
					if (limit == NULL)
						errx_exit("cannot find limit \"%s\" for rule \"%s\" in the configuration file",
						    opt_limit, opt_rule);
				}
				break;
			}
		}

		if (rule == NULL)
			errx_exit("cannot find rule \"%s\" in the configuration file(s)", opt_rule);

		if (opt_limit == NULL)
			commandsp = cmd_code & CMD_STARTUP ? &rule->rc[0] : &rule->rc[1];
		else {
			if (cmd_code & CMD_STARTUP)
				commandsp = &limit->rc[0];
			else if (cmd_code & CMD_SHUTDOWN)
				commandsp = &limit->rc[1];
			else if (cmd_code & CMD_EXPIRE) {
				commandsp = &commands_tmp;
				commands_tmp.cmd = limit->expire.cmd;
				commands_tmp.ncmd = limit->expire.ncmd;
			} else { /* cmd_code & CMD_REACH */
				commandsp = &commands_tmp;
				commands_tmp.cmd = limit->reach.cmd;
				commands_tmp.ncmd = limit->reach.ncmd;
			}
		}
	}
	return run_opt_command(commandsp, cmd_code);
}

/*
 * Sometime ipa(8) has to create main database directory with
 * permission bits r-xr-xr-x, database lock file with permission
 * bits r--r--r--.
 *
 * In other case we should prevent ipa(8) from creating directories and
 * files in the database with following permission bits -w--w-rwx.
 *
 * This subroutine changes current umask, return old umask value and
 * informs about changes in umask value.
 */
mode_t
Umask(mode_t numask)
{
	mode_t	old_numask;

	old_numask = umask(numask);
	if (old_numask == numask)
		syslog(LOG_INFO, "current umask is 0%03o", numask);
	else
		syslog(LOG_INFO, "umask is changed 0%03o -> 0%03o", old_numask, numask);
	return old_numask;
}
