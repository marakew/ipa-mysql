/*-
 * Copyright (c) 2001-2003 Andrey Simonenko
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
 *   @(#)$Id: kpf.h,v 1.3.2.3 2003/07/08 08:30:01 simon Exp $
 */

#ifndef IPA_KPF_H
#define IPA_KPF_H

#ifndef WITHOUT_PF

#include <sys/param.h>

/*
 * Packet Filter was introduced in OpenBSD 3.0.
 */
#if (defined(OpenBSD) && (OpenBSD >= 200111)) || defined(WITH_PF)

#ifndef WITH_PF
# define WITH_PF
#endif

#define PF_NUMBER_MAX UINT_MAX

extern int	use_pf;
extern u_quad_t *kpf;
extern u_int	nkpf;

extern int	kpf_init(void);
extern void	kpf_close(void);
extern int	kpf_read_table(void);

#endif /* (defined(OpenBSD) && (OpenBSD >= 200111)) || defined(WITH_PF) */

#endif /* !WITHOUT_PF */

#endif /* IPA_KPF_H */
