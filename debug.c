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
  "@(#)$Id: debug.c,v 1.6.2.3 2003/07/08 08:30:01 simon Exp $";
#endif /* !lint */

#include "debug.h"
#include "system.h"

#include "kpf.h"

#ifdef __FreeBSD__
# include "kipfw.h"
# include "kip6fw.h"
#endif

int		debug_exec, debug_limit, debug_time, debug_lock,
		debug_include, debug_worktime;

static int	BACKUP_VAR_NAME(debug_exec), BACKUP_VAR_NAME(debug_limit),
		BACKUP_VAR_NAME(debug_time), BACKUP_VAR_NAME(debug_include),
		BACKUP_VAR_NAME(debug_lock), BACKUP_VAR_NAME(debug_worktime);
		

#ifdef WITH_IPFW
int		debug_ipfw;
static int	BACKUP_VAR_NAME(debug_ipfw);
#endif

#ifdef WITH_IP6FW
int		debug_ip6fw;
static int	BACKUP_VAR_NAME(debug_ip6fw);
#endif

#ifdef WITH_IPFIL
int		debug_ipfil;
static int	BACKUP_VAR_NAME(debug_ipfil);
#endif

#ifdef WITH_PF
int		debug_pf;
static int	BACKUP_VAR_NAME(debug_pf);
#endif

/*
 * Reset all debug variables (i.e. set them to default value).
 */
void
reset_debug(void)
{
#ifdef WITH_IPFW
	debug_ipfw = 
#endif
#ifdef WITH_IP6FW
	debug_ip6fw =
#endif
#ifdef WITH_PF
	debug_pf =
#endif
#ifdef WITH_IPFIL
	debug_ipfil =
#endif
	debug_exec = debug_limit = debug_time = debug_worktime = debug_lock = 0;
	debug_include = 1;
}

/*
 * Backup current values of debug_* parameters.
 */
void
backup_debug(void)
{
#ifdef WITH_IPFW
	BACKUP_VAR(debug_ipfw);
#endif
#ifdef WITH_IP6FW
	BACKUP_VAR(debug_ip6fw);
#endif
#ifdef WITH_PF
	BACKUP_VAR(debug_pf);
#endif
#ifdef WITH_IPFIL
	BACKUP_VAR(debug_ipfil);
#endif
	BACKUP_VAR(debug_exec);
	BACKUP_VAR(debug_limit);
	BACKUP_VAR(debug_time);
	BACKUP_VAR(debug_worktime);
	BACKUP_VAR(debug_lock);
	BACKUP_VAR(debug_include);
}

/*
 * Restore values of backup_* parameters from backuped copies.
 */
void
restore_debug(void)
{
#ifdef WITH_IPFW
	RESTORE_VAR(debug_ipfw);
#endif
#ifdef WITH_IP6FW
	RESTORE_VAR(debug_ip6fw);
#endif
#ifdef WITH_PF
	RESTORE_VAR(debug_pf);
#endif
#ifdef WITH_IPFIL
	RESTORE_VAR(debug_ipfil);
#endif
	RESTORE_VAR(debug_exec);
	RESTORE_VAR(debug_limit);
	RESTORE_VAR(debug_time);
	RESTORE_VAR(debug_worktime);
	RESTORE_VAR(debug_lock);
	RESTORE_VAR(debug_include);
}
