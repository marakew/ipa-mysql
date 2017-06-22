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
 *  @(#)$Id: debug.h,v 1.6.2.2 2003/07/08 08:30:01 simon Exp $
 */

#ifndef IPA_DEBUG_H
#define IPA_DEBUG_H

#include "system.h"

#define BACKUP_VAR_NAME(var)	var ## _bkp
#define BACKUP_VAR(var)		BACKUP_VAR_NAME(var) = var
#define RESTORE_VAR(var)	var = BACKUP_VAR_NAME(var)

extern int	debug_exec, debug_limit, debug_time, debug_lock, debug_include,
		debug_worktime;

#ifdef __FreeBSD__
# include "kipfw.h"
# include "kip6fw.h"

# ifdef WITH_IPFW
extern int	debug_ipfw;
# endif

# ifdef WITH_IP6FW
extern int	debug_ip6fw;
# endif
#endif /* __FreeBSD__ */

#ifdef WITH_IPFIL
extern int	debug_ipfil;
#endif

#include "kpf.h"

#ifdef WITH_PF
extern int	debug_pf;
#endif

extern void	reset_debug(void);
extern void	backup_debug(void);
extern void	restore_debug(void);

#endif /* !IPA_DEBUG_H */
