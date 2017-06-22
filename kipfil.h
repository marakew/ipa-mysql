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
 *   @(#)$Id: kipfil.h,v 1.6.2.3 2003/03/27 11:13:31 simon Exp $
 */


#ifndef IPA_KIPFIL_H
#define IPA_KIPFIL_H

#include "system.h"

#ifdef WITH_IPFIL

#define IPFIL_RULE_NUMBER_MAX UINT_MAX

#if IPF_VERSION > 30400
# define IPFIL_GROUP_NUMBER_MAX UINT_MAX
#else
# define IPFIL_GROUP_NUMBER_MAX USHRT_MAX
#endif /* IPF_VERSION > 30400 */

struct kipfil_group {
	u_int		group_number;	/* Group number. */
	int		exist;		/* 1, if group exists. */
	u_quad_t	*bcnt;		/* Array of byte counters. */
	u_int		bcnt_size;	/* Size of *bcnt array and number of
					   rules in the group. */
};

struct kipfil {
	struct kipfil_group	*group;	/* Array of groups. */
	u_int		ngroup;		/* Number of groups. */
	char		type;		/* 'i' or 'o'. */
};

extern int		use_ipfil, use_ipfil_in, use_ipfil_out;
extern struct kipfil	kipfil_in, kipfil_out;
extern u_quad_t		kipfil_bcnt_max;

extern int		kipfil_init(void);
extern void		kipfil_close(void);
extern int		kipfil_read_tables(void);


#endif /* WITH_IPFIL */

#endif /* IPA_KIPFIL_H */
