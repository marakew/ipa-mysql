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
 *
 *   @(#)$Id: kipfw.h,v 1.5.2.1 2003/03/05 16:09:23 simon Exp $
 */


#ifndef IPA_KIPFW_H
#define IPA_KIPFW_H

#ifndef WITHOUT_IPFW

#define WITH_IPFW

#include <sys/types.h>
#ifndef IPFW2
# include <sys/queue.h>
#endif
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>

#define IPFW_NUMBER_MAX	USHRT_MAX

#ifdef IPFW2
# define IPFW_BCNT(x)		(x.bcnt)
# define IPFWP_BCNT(p)		(p->bcnt)
# define IPFWP_NUMBER(p)	(p->rulenum)
#else
# define IPFW_BCNT(x)		(x.fw_bcnt)
# define IPFWP_BCNT(p)		(p->fw_bcnt)
# define IPFWP_NUMBER(p)	(p->fw_number)
#endif /* IPFW2 */

extern int		use_ipfw;
extern u_quad_t		kipfw_bcnt_max;
extern struct ip_fw	*kipfw;

extern int	kipfw_init(void);
extern void	kipfw_close(void);
extern int	kipfw_read_table(void);

#endif /* !WITHOUT_IPFW */

#endif /* IPA_KIPFW_H */
