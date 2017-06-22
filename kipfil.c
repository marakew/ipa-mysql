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
  "@(#)$Id: kipfil.c,v 1.6.2.8 2003/11/11 10:23:42 simon Exp $";
#endif /* !lint */

#include "system.h"

#ifdef WITH_IPFIL

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <paths.h>

#include <limits.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#ifdef IP_COMPAT_H
# include IP_COMPAT_H
#else
# include <netinet/ip_compat.h>
#endif

#ifdef IP_FIL_H
# include IP_FIL_H
#else
# include <netinet/ip_fil.h>
#endif

#include "kipfil.h"

#include "debug.h"


#ifdef _PATH_KMEM
# define KMEMDEV	_PATH_KMEM
#else
# define KMEMDEV	"/dev/kmem"
#endif

#ifdef IPL_NAME
# define IPLDEV IPL_NAME
#else
# define IPLDEV	"/dev/ipl"
#endif


/*
 * We have two separate structures for "ingoing" and "outgoing"
 * IPFIL kernel accounting tables.
 */
struct kipfil	kipfil_in  = { NULL, 0, 'i' },
		kipfil_out = { NULL, 0, 'o' };

u_quad_t	kipfil_bcnt_max; /* Max value of IP Filter byte counter. */

int		use_ipfil,	/* 1, if some rule{} uses "ipfil" parameter. */
		use_ipfil_in,	/* 1, if we need "ingoing" accounting rules. */
		use_ipfil_out;	/* 1, if we need "outgoing" accounting rules. */

static const char	*kmemdev = KMEMDEV;
static const char	*ipldev = IPLDEV;

static int	kmemfd = -1, iplfd = -1; /* FD for kmemdev and ipldev. */

static struct kipfil *curkipfil; /* Pointer to kipfil_in or kipfil_out. */
static int	new_group_flag;	/* 1, if a new group was added in curkipfil. */

static int	curqueue;	/* FR_INQUE or FR_OUTQUE (IP Filter). */

/*
 * Read data from the /dev/kmem device.
 * Return -1 if an error occured, else return number of read bytes.
 */
static int
kmemread(void *vptr, off_t offset, size_t n)
{
	size_t		nleft = n;	/* How many is left to read. */
	ssize_t		nread;		/* How many have been already read. */
	char		*ptr = vptr;	/* Pointer to buffer. */

	if (lseek(kmemfd, offset, SEEK_SET) < 0) {
		syslog(LOG_ERR, "kmemread: lseek(%s, %qu): %m", kmemdev, (u_quad_t)offset);
		return -1;
	}
	while (nleft > 0) {
		if ( (nread = read(kmemfd, ptr, nleft)) < 0) {
			syslog(LOG_ERR, "kmemread: read(FD %d): %m", kmemfd);
			return -1;
		} else if (nread == 0)
			break;	/* EOF */
		nleft -= nread;
		ptr += nread;
	}
	return n - nleft;
}

/*
 * Init IP Filter support: open /dev/kmem, /dev/ipl devices.
 */
int
kipfil_init(void)
{
	struct frentry	frent;

	syslog(LOG_INFO, "init IP Filter support");
	if ( (kmemfd = open(kmemdev, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "kipfil_init: open(%s, O_RDONLY): %m", kmemdev);
		syslog(LOG_ERR, "IP Filter is not configured in the kernel or doesn't work properly");
		return -1;
	}
	if ( (iplfd = open(ipldev, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "kipfil_init: open(%s, O_RDONLY): %m", ipldev);
		syslog(LOG_ERR, "IP Filter is not configured in the kernel or doesn't work properly");
		return -1;
	}

	switch (sizeof(frent.fr_bytes)) {
	case 4:
		kipfil_bcnt_max = ULONG_MAX;
		break;
	case 8:
		kipfil_bcnt_max = UQUAD_MAX;
		break;
	default:
		syslog(LOG_ERR, "kipfil_init: unsupported size of fr_bytes (%d bytes) in struct frentry",
		    sizeof frent.fr_bytes);
		return -1;
	}

	if (debug_ipfil > 0) {
		syslog(LOG_INFO, "kipfil_init: %s opened, FD = %d", kmemdev, kmemfd);
		syslog(LOG_INFO, "kipfil_init: %s opened, FD = %d", ipldev, iplfd);
		syslog(LOG_INFO, "kipfil_init: sizeof(fr_bytes) = %u", sizeof frent.fr_bytes);
	}
	return 0;
}

/*
 * Free memory held by curkipfil.
 */
static void
kipfil_free_table(void)
{
	u_int		i;
	struct kipfil_group *groupp;

	if (debug_ipfil > 0)
		syslog(LOG_INFO, "kipfil_free_table: free local memory for \"%s\" table",
		    curkipfil->type == 'i' ? "in" : "out");

	for (i = 0, groupp = curkipfil->group; i < curkipfil->ngroup; ++groupp, ++i)
		free(groupp->bcnt);
	free(curkipfil->group);
	curkipfil->group = NULL;
	curkipfil->ngroup = 0;
}

/*
 * Remove IP Filter support: close descriptors for opened
 * /dev/kmem and /dev/ipl devices.  Free local memory.
 */
void
kipfil_close(void)
{
	syslog(LOG_INFO, "remove IP Filter support");
	if (kmemfd != -1) {
		if (close(kmemfd) < 0)
			syslog(LOG_ERR, "kipfil_close: close(FD %d (%s)): %m",
			    kmemfd, kmemdev);
		kmemfd = -1;
	}
	if (iplfd != -1) {
		if (close(iplfd) < 0)
			syslog(LOG_ERR, "kipfil_close: close(FD %d (%s)): %m",
			    iplfd, ipldev);
		iplfd = -1;
	}
	curkipfil = &kipfil_in;
	kipfil_free_table();
	curkipfil = &kipfil_out;
	kipfil_free_table();
}

/*
 * Dump IPFIL rules from curkipfil to syslog(3).
 */
static void
kipfil_dump_table(void)
{
#define TXT_BUF_LEN 60
	int		len, total_len = 0;
	char		txt_buf[TXT_BUF_LEN + 1];
	char		one_rule[1 + 10 + 1 + 10 + 1];
	const char	*gtype = curkipfil->type == 'i' ? "in" : "out";
	/*
	 *  1 - ' '
	 * 10 - length of group number (u_int or u_short)
	 *  1 - '@'
	 * 10 - length of rule number (u_int)
	 *  1 - '\0'
	 */
	u_int		gi;	/* Group index. */
	u_int		ri;	/* Rule index + 1. */
	struct kipfil_group	*kgroupp;

	if (curkipfil->group == NULL) {
		syslog(LOG_INFO, "kipfil_dump_table: \"%s\" IPFIL table is empty", gtype);
		return;
	}
	syslog(LOG_INFO, "kipfil_dump_table: dump \"%s\" IPFIL table:", gtype);
	for (gi = 0, kgroupp = curkipfil->group; gi < curkipfil->ngroup; ++kgroupp, ++gi)
		for (ri = 1; ri <= kgroupp->bcnt_size; ++ri) {
			if (kgroupp->group_number == 0)
				len = snprintf(one_rule, sizeof(one_rule), " @%u", ri);
			else
				len = snprintf(one_rule, sizeof(one_rule), " %u@%u",
				    (u_int)kgroupp->group_number, ri);
			if (len < 0) {
				syslog(LOG_ERR, "kipfil_dump_table: snprintf failed: %m");
				continue;
			}
			if (len + 1 > sizeof(one_rule)) {
				syslog(LOG_ERR, "kipfil_dump_table: not enough space (%d chars) in one_rule", len + 1);
				continue;
			}
			len = strlen(one_rule);
			if (total_len + len > TXT_BUF_LEN) {
				syslog(LOG_INFO, "  **%s", txt_buf);
				total_len = 0;
			}
			strcpy(txt_buf + total_len, one_rule);
			total_len += len;
		}
	if (total_len > 0)
		/* Log the rest of txt_buf. */
		syslog(LOG_INFO, "  **%s", txt_buf);
#undef TXT_BUF_LEN
}

/*
 * Clean groups in curkipfil: if exist == 0 in some group,
 * then this group does not exist in IPFIL kernel table any more,
 * so, remove it and its local memory.
 */
static int
kipfil_clean_groups(void)
{
	u_int		i, j;
	size_t		size;
	struct kipfil_group	*kgroupp;

	for (i = 0, kgroupp = curkipfil->group; i < curkipfil->ngroup;)
		if (!kgroupp->exist) {
			if (debug_ipfil > 0)
				syslog(LOG_INFO, "kipfil_clean_groups: group %c%u was removed from IPFIL kernel table",
				    curkipfil->type, kgroupp->group_number);
			free(kgroupp->bcnt);
			for (j = i; j < curkipfil->ngroup - 1; ++j)
				/* Shift all structures. */
				*kgroupp = *(kgroupp + 1);
			--curkipfil->ngroup;
			size = curkipfil->ngroup * sizeof *curkipfil->group;
			if ( (curkipfil->group = realloc(curkipfil->group, size)) == NULL) {
				syslog(LOG_ERR, "kipfil_clean_groups: realloc(%d bytes): %m", size);
				return -1;
			}
			kgroupp = curkipfil->group + i;
		} else {
			++kgroupp;
			++i;
		}
	return 0;
}

/*
 * Reset groups in curkipfil: set exist = 0 for every group,
 * frentry_read_list() will set it to real value.
 */
static void
kipfil_reset_groups(void)
{
	u_int		i;
	struct kipfil_group	*kgroupp;

	for (i = 0, kgroupp = curkipfil->group; i < curkipfil->ngroup; ++kgroupp, ++i)
		kgroupp->exist = 0;
}

/*
 * Read rules from the group (in the first call read data for the group 0)
 * and if some rule is a head of the another group, then recursively read
 * rules from this group.
 */
static int
frentry_read_list(const struct frentry *frentp)
{
	u_int		ri;		/* Rule index in current group. */
	u_int		group_index = 0;/* For saving index for current group.
					   Initial value isn't used. */
	size_t		size;		/* Temporary variable. */
	struct frentry	frent;		/* Buffer for actual data from the kernel. */
	struct kipfil_group *kgroupp = NULL; /* Pointer to current group, also is used as a flag. */

	for (ri = 1; frentp != NULL; frentp = frent.fr_next, ++ri) {
		/* Read actual data from the kernel. */
		if (kmemread(&frent, (u_long)frentp, sizeof(struct frentry)) != sizeof(struct frentry)) {
			syslog(LOG_ERR, "frentry_read_list: kmemread failed for %c%u@%u, offset = %lu",
			    frentp->fr_flags & FR_OUTQUE ? 'o' : frentp->fr_flags & FR_INQUE ? 'i' : '?',
			    frentp->fr_group, ri, (u_long)frentp);
			return -1;
		}

		/*
		 * Check fr_flags for valid values.
		 */
		if ((frent.fr_flags & (FR_INQUE | FR_OUTQUE)) != curqueue) {
			if (((frent.fr_flags & (FR_INQUE | FR_OUTQUE)) != FR_INQUE) &&
			    ((frent.fr_flags & (FR_INQUE | FR_OUTQUE)) != FR_OUTQUE))
				syslog(LOG_WARNING, "frentry_read_list: unknown/incorrect type of frentry (fr_flags = 0x%x) for ?%u@%u",
				    (u_int)frent.fr_flags, (u_int)frent.fr_group, ri);
			else
				syslog(LOG_WARNING, "frentry_read_list: rule %c%u@%u belongs to \"%s\" list",
				    frent.fr_flags & FR_INQUE ? 'i' : 'o', (u_int)frent.fr_group, ri, curkipfil->type == 'i' ? "in" : "out");
			syslog(LOG_WARNING, "frentry_read_list: assume this IPFIL rule as %c%u@%u",
			    curkipfil->type, (u_int)frent.fr_group, ri);
			syslog(LOG_WARNING, "Double check your IP Filter configuration file syntax!!!");
		}

		/*
		 * Save accounting information for read rule.
		 * We use kgroupp pointer as a flag here, see below why.
		 */
		if (kgroupp == NULL) {
			int	found_group_flag = 0;
			u_int	gi;	/* Local group index. */

			/* Try to find an entry for this group. */
			for (gi = 0, kgroupp= curkipfil->group; gi < curkipfil->ngroup; ++kgroupp, ++gi) {
				if (kgroupp->group_number == frent.fr_group) {
					found_group_flag = 1;
					group_index = gi;
					break;
				}
				/*
				 * Groups, which existed or were added in previous
				 * kipfil_read_tables() call, are sorted.  Groups,
				 * which were added in this kipfil_read_tables() call,
				 * are not sorted, but we will not find current
				 * group there.  So, it is safe to do this check
				 * without checking new_group_flag.
				 */
				if (frent.fr_group < kgroupp->group_number)
					break;
			}
			if (!found_group_flag) {
				/* Need to add a new group -> table becomes changed. */
				if (debug_ipfil > 0)
					syslog(LOG_INFO, "frentry_read_list: new group %c%u in IPFIL kernel table",
					    curkipfil->type, frent.fr_group);
				size = ++curkipfil->ngroup * sizeof *curkipfil->group;
				if ( (curkipfil->group = realloc(curkipfil->group, size)) == NULL) {
					syslog(LOG_ERR, "frentry_read_list: realloc(%d bytes): %m", size);
					return -1;
				}
				group_index = curkipfil->ngroup - 1;
				kgroupp = curkipfil->group + group_index;
				kgroupp->group_number = frent.fr_group;
				kgroupp->bcnt = NULL;
				kgroupp->bcnt_size = 0;
				new_group_flag = 1;
			}
		} else if (new_group_flag)
			/*
			 * We should recalculate kgroupp pointer, because
			 * memory curkipfil->group points to was reallocated.
			 */
			kgroupp = curkipfil->group + group_index;

		if (ri > kgroupp->bcnt_size) {
			/* New rule in the group -> need to resize table. */
			size = ++kgroupp->bcnt_size * sizeof *kgroupp->bcnt;
			if ( (kgroupp->bcnt = realloc(kgroupp->bcnt, size)) == NULL) {
				syslog(LOG_ERR, "frentry_read_list: realloc(%d bytes): %m", size);
				return -1;
			}
		}
		kgroupp->bcnt[ri - 1] = frent.fr_bytes;

		if (frent.fr_grp != NULL)
			/* Read the next group (recursive call). */
			if (frentry_read_list(frent.fr_grp) < 0)
				return -1;
	}

	/*
	 * All rules for the current group were read.
	 * If *bcnt for this group holds more memory than we need,
	 * then descrease this memory.
	 */
	--ri;	/* Number of rules in the group. */
	if (new_group_flag)
		/* See above why we should recalculate kgroupp. */
		kgroupp = curkipfil->group + group_index;
	if (ri < kgroupp->bcnt_size) {
		/* Number of elements in the group was decreased. */
		if (debug_ipfil > 0)
			syslog(LOG_INFO, "frentry_read_list: decrease group %c%u: old bcnt_size = %u, new bcnt_size = %u",
			    curkipfil->type, kgroupp->group_number, kgroupp->bcnt_size, ri);
		size = ri * sizeof *kgroupp->bcnt;
		if ( (kgroupp->bcnt = realloc(kgroupp->bcnt, size)) == NULL) {
			syslog(LOG_ERR, "frentry_read_list: realloc(%d bytes): %m", size);
			return -1;
		}
		kgroupp->bcnt_size = ri;
	}
	kgroupp->exist = 1; /* Group exists. */
	return 0;
}

/*
 * Compare two kipfil_group structures by group number.
 */
static int
cmp_kipfil_group(const void *p1, const void *p2)
{
	return ((const struct kipfil_group *)p1)->group_number >
	       ((const struct kipfil_group *)p2)->group_number ? 1 : -1;
}

/*
 * Read "in" and "out" IP Filter kernel accounting tables.
 */
int
kipfil_read_tables(void)
{
	int		set;
	struct friostat	frio;
#if IPF_VERSION >= 30400
	struct friostat *friop = &frio;
#endif
	struct frentry	*frentp;

	bzero(&frio, sizeof frio);

#if IPF_VERSION >= 30400
	if (ioctl(iplfd, SIOCGETFS, &friop) < 0) {
#else
	if (ioctl(iplfd, SIOCGETFS, &frio) < 0) {
#endif
		syslog(LOG_ERR, "kipfil_read_table: ioctl(SIOCGETFS): %m");
		return -1;
	}

	set = frio.f_active;

	/* Outgoing accounting table. */
	if (use_ipfil_out) {
		frentp = frio.f_acctout[set];
		curkipfil = &kipfil_out;
		if (frentp != NULL) {
			new_group_flag = 0;
			kipfil_reset_groups();
			curqueue = FR_OUTQUE;
			if (frentry_read_list(frentp) < 0)
				return -1;
			if (new_group_flag)
				qsort(kipfil_out.group, kipfil_out.ngroup, sizeof *kipfil_out.group, cmp_kipfil_group);
			if (kipfil_clean_groups() < 0)
				return -1;
		} else if (kipfil_out.group != NULL)
			/* "out" IPFIL kernel table became empty. */
			kipfil_free_table();

		if (debug_ipfil > 1)
			kipfil_dump_table();
	}

	/* Ingoing accounting table. */
	if (use_ipfil_in) {
		frentp = frio.f_acctin[set];
		curkipfil = &kipfil_in;
		if (frentp != NULL) {
			new_group_flag = 0;
			kipfil_reset_groups();
			curqueue = FR_INQUE;
			if (frentry_read_list(frentp) < 0)
				return -1;
			if (new_group_flag)
				qsort(kipfil_in.group, kipfil_in.ngroup, sizeof *kipfil_in.group, cmp_kipfil_group);
			if (kipfil_clean_groups() < 0)
				return -1;
		} else if (kipfil_in.group != NULL)
			/* "in" IPFIL kernel table became empty. */
			kipfil_free_table();

		if (debug_ipfil > 1)
			kipfil_dump_table();
	}
	return 0;
}

#endif /* WITH_IPFIL */
