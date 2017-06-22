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
 *   @(#)$Id: kip6fw.h,v 1.5.2.1 2003/03/05 16:09:23 simon Exp $
 */


#ifndef IPA_KIP6FW_H
#define IPA_KIP6FW_H

#include <osreldate.h>
#include <sys/types.h>

/*
 * There were bugs in IPv6 Firewall implementation since FreeBSD 4.0-RELEASE (?)
 * and ipa(8) started to work correctly with IPv6 Firewall after
 * FreeBSD 4.2-RELEASE, when those bugs were fixed.
 */

#if !defined(WITHOUT_IP6FW) && ((__FreeBSD_version >= 420001) || defined(WITH_IP6FW))

#ifdef WITH_IP6FW
# define WITH_IP6FW_OPT
#else
# define WITH_IP6FW
#endif

#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_fw.h>

#define IP6FW_NUMBER_MAX USHRT_MAX

extern int		use_ip6fw;
extern u_quad_t		kip6fw_bcnt_max;
extern struct ip6_fw	*kip6fw;

extern int	kip6fw_init(void);
extern void	kip6fw_close(void);
extern int	kip6fw_read_table(void);

#endif

#endif /* IPA_KIP6FW_H */
