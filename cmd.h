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
 *
 *   @(#)$Id: cmd.h,v 1.6.2.1 2003/02/19 22:04:33 simon Exp $
 */

#ifndef IPA_CMD_H
#define IPA_CMD_H


struct cmd {
	char		*str;		/* command string */
	u_long		uid;		/* UID */
	u_long		gid;		/* GID */
	gid_t		*suppl_gid;	/* supplementary GIDs */
	u_int		nsuppl_gid;	/* size of prev. array */
	short		uid_set, uid_named;
	short		gid_set, gid_named;
};

struct commands {
	struct cmd	*cmd;
	u_int		ncmd;
	struct cmd	*cmd_if_limit;
	u_int		ncmd_if_limit;
	struct cmd	*cmd_if_nolimit;
	u_int		ncmd_if_nolimit;
};

#define CMD_STARTUP	0x01
#define CMD_SHUTDOWN	0x02
#define CMD_REACH	0x04
#define CMD_EXPIRE	0x08
#define CMD_IF_LIMIT	0x10
#define CMD_IF_NOLIMIT	0x20

#ifdef __GNUC__
extern int	exec_cmd_list(const struct cmd *, u_int, const char *, ...) __attribute__ ((format (printf, 3, 4)));
extern pid_t	exec_cmd_list_bg(const struct cmd *, u_int, const char *, ...) __attribute__ ((format (printf, 3, 4)));
#else
extern int	exec_cmd_list(const struct cmd *, u_int, const char *, ...);
extern pid_t	exec_cmd_list_bg(const struct cmd *, u_int, const char *, ...);
#endif
extern void	free_cmd_list(struct cmd *, u_int);
extern void	free_commands(struct commands *);
extern int	run_opt_command(const struct commands *, u_int);

#endif /* !IPA_CMD_H */
