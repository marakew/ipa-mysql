##
## Copyright (c) 1999-2003 Andrey Simonenko
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the above copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
##

# @(#)$Id: Makefile,v 1.6.2.9 2003/11/11 10:24:34 simon Exp $


#
# CC - C compiler, GCC is prefered.
#
CC?=		/usr/bin/cc

#
# CFLAGS - flags to CC:
#	-Wall - most of warnings;
#	-Ox   - optimize;
#	-g    - produce debugging information.
#
#CFLAGS=		-Wall -O1 -g

#
# PREFIX - prefix for all below listed paths
#
PREFIX?=	/usr/local

#
# DST_BIN_DIR - where to install binaries
#
DST_BIN_DIR=	${PREFIX}/bin

#
# DST_MAN_DIR - where to install manuals
#
DST_MAN_DIR=	${PREFIX}/man

#
# DST_ETC_DIR - where to install template configuration
#
DST_ETC_DIR=	${PREFIX}/etc

#
# DST_RC_DIR - where to install sample rc-script
#
DST_RC_DIR=	${PREFIX}/etc/rc.d

#
# MySQL - library and include files locations (correct this if is needed!)
#
MYSQLLIBDIR=   /usr/local/lib/mysql
MYSQLINCDIR=   /usr/local/include/mysql

#
# DST_EXAMPLE_DIR - where to install examples
#
DST_EXAMPLE_DIR=	${PREFIX}/share/examples/ipa

CAT?=		/bin/cat
RM?=		/bin/rm
LN?=		/bin/ln
ECHO?=		/bin/echo
INSTALL?=	/usr/bin/install
UNAME?=		/usr/bin/uname
MKDIR?=		/bin/mkdir

#
# INSTALL_* variables
#
INSTALL_MAN=		${INSTALL} -c -g wheel -o root -m 0444
INSTALL_DATA=		${INSTALL} -c -g wheel -o root -m 0444
INSTALL_PROGRAM=	${INSTALL} -c -g wheel -o root -m 0555
INSTALL_SCRIPT=		${INSTALL} -c -g wheel -o root -m 0500 
#INSTALL_MAN=		${BSD_INSTALL_MAN}
#INSTALL_DATA=		${BSD_INSTALL_DATA}
#INSTALL_PROGRAM=	${BSD_INSTALL_PROGRAM}
#INSTALL_SCRIPT=		${BSD_INSTALL_SCRIPT}
INSTALL_MAN_DIR=	${INSTALL} -d -m 0555 -g wheel -o root
INSTALL_DATA_DIR=	${INSTALL} -d -m 0555 -g wheel -o root

OS!=		${UNAME} -s

.PHONY: checkos install deinstall clean

IPA=		ipa.o cmd.o common.o config.o db.o debug.o kipfil.o rules.o
IPASTAT=	ipastat.o common.o

.if defined(WITH_MYSQL)
MYSQLLIB=      mysqlclient
CFLAGS+=       -I${MYSQLINCDIR}
#LDFLAGS+=      -L${MYSQLLIBDIR} -l${MYSQLLIB}
LDMYSQLFLAGS=	-L${MYSQLLIBDIR} -l${MYSQLLIB}
CFLAGS+=	-DWITH_MYSQL
IPA+=		mysql.o
.endif

.MAIN: checkos ${OS}

checkos:
.if ${OS} != "FreeBSD" && ${OS} != "NetBSD" && ${OS} != "OpenBSD"
	@${ECHO}
	@${ECHO} ">> IPA-`${CAT} Version` is designed for FreeBSD, NetBSD and OpenBSD."
	@${ECHO} ">> Your operating system is ${OS}."
	@${ECHO}
	@exit 1
.endif
.if !exists(./system.h)
. ifdef WITHOUT_IPFIL
	@./gensysinfo -DWITHOUT_IPFIL
. else
	@./gensysinfo
. endif
.endif
	@${ECHO} ">> Building for ${OS} system"

.ifdef WITHOUT_IPFW
CFLAGS+=	-DWITHOUT_IPFW
.endif
.ifdef IPFW2
CFLAGS+=	-DIPFW2
.endif
.ifdef WITHOUT_IPFIL
CFLAGS+=	-DWITHOUT_IPFIL
.endif
.ifdef WITHOUT_IP6FW
CFLAGS+=	-DWITHOUT_IP6FW
.elifdef WITH_IP6FW
CFLAGS+=	-DWITH_IP6FW
.endif
.ifdef WITHOUT_PF
CFLAGS+=	-DWITHOUT_PF
.endif

.ifdef WITH_PF
CFLAGS+=	-DWITH_PF
.ifdef PF_INCLUDE_DIR
CFLAGS+=	-I${PF_INCLUDE_DIR}
.endif
.endif

.ifmake FreeBSD
IPA+=		kipfw.o kip6fw.o
.endif

.if make(OpenBSD) || defined(WITH_PF)
IPA+=		kpf.o
.endif

FreeBSD NetBSD OpenBSD: ipa ipastat

ipa: ${IPA}
	${CC} -o ${.TARGET} ${LDFLAGS} ${LDMYSQLFLAGS} ${IPA}
	strip ipa

ipastat: ${IPASTAT}
	${CC} -o ${.TARGET} ${LDFLAGS} ${IPASTAT}
	strip ipastat

ipa.o: ipa.c ipa.h cmd.h config.h common.h db.h kipfil.h kpf.h kipfw.h kip6fw.h path.h rules.h system.h
	${CC} ${CFLAGS} -o ${.TARGET} -c ipa.c

ipastat.o: ipastat.c ipastat.h common.h path.h version.h
	${CC} ${CFLAGS} -o ${.TARGET} -c ipastat.c

mysql.o: mysql.c mysql.h
	${CC} ${CFLAGS} -o ${.TARGET} -c mysql.c

db.o: db.c db.h debug.h common.h config.h ipa.h path.h rules.h
	${CC} ${CFLAGS} -o ${.TARGET} -c db.c

common.o: common.c common.h system.h version.h
	${CC} ${CFLAGS} -o ${.TARGET} -c common.c

rules.o: rules.c rules.h db.h cmd.h common.h config.h debug.h kipfil.h kipfw.h kip6fw.h kpf.h path.h system.h
	${CC} ${CFLAGS} -o ${.TARGET} -c rules.c

kipfw.o: kipfw.c kipfw.h debug.h
	${CC} ${CFLAGS} -o ${.TARGET} -c kipfw.c

kip6fw.o: kip6fw.c kip6fw.h debug.h
	${CC} ${CFLAGS} -o ${.TARGET} -c kip6fw.c

kipfil.o: kipfil.c kipfil.h debug.h system.h
	${CC} ${CFLAGS} -o ${.TARGET} -c kipfil.c

kpf.o: kpf.c kpf.h debug.h
	${CC} ${CFLAGS} -o ${.TARGET} -c kpf.c

config.o: config.c config.h common.h db.h debug.h ipa.h kipfw.h kip6fw.h kpf.h path.h rules.h system.h \
	mysql.h mysql.c
	${CC} ${CFLAGS} -o ${.TARGET} -c config.c

cmd.o: cmd.c cmd.h debug.h ipa.h
	${CC} ${CFLAGS} -o ${.TARGET} -c cmd.c

debug.o: debug.c debug.h kpf.h kipfw.h kip6fw.h system.h
	${CC} ${CFLAGS} -o ${.TARGET} -c debug.c

clean:
	@${ECHO} ">> Cleaning object, binary and core files"
	${RM} -f *.o ipa ipastat *.core system.h

deinstall:
	@${ECHO} ">> Deinstalling binaries, manual pages and miscellaneous files"
	${RM} ${DST_BIN_DIR}/ipa ${DST_BIN_DIR}/ipastat
	${RM} -r ${DST_EXAMPLE_DIR}
	${RM} ${DST_MAN_DIR}/man5/ipa.conf.5 ${DST_MAN_DIR}/man5/ipa.5 ${DST_MAN_DIR}/man8/ipa.8 ${DST_MAN_DIR}/man8/ipastat.8
	${RM} ${DST_MAN_DIR}/ru_RU.KOI8-R/man5/ipa.conf.5 ${DST_MAN_DIR}/ru_RU.KOI8-R/man5/ipa.5 ${DST_MAN_DIR}/ru_RU.KOI8-R/man8/ipa.8 ${DST_MAN_DIR}/ru_RU.KOI8-R/man8/ipastat.8
	${RM} ${DST_ETC_DIR}/ipa.conf.default ${DST_RC_DIR}/ipa.sh.sample
	
install:
.if !exists(./ipa) || !exists(./ipastat)
	@${ECHO}
	@${ECHO} ">> You should build binaries before install them."
	@${ECHO}
	@exit 1
.endif
	@${ECHO} ">> Installing binaries, manual pages and miscellaneous files"
	${INSTALL_PROGRAM} ipa ipastat ${DST_BIN_DIR}
	${INSTALL_MAN} man/ipa.5 man/ipa.conf.5 ${DST_MAN_DIR}/man5
	${INSTALL_MAN} man/ipa.8 man/ipastat.8 ${DST_MAN_DIR}/man8
.if !exists(${DST_MAN_DIR}/ru_RU.KOI8-R/man5)
	${INSTALL_MAN_DIR} ${DST_MAN_DIR}/ru_RU.KOI8-R/man5
.endif
.if !exists(${DST_MAN_DIR}/ru_RU.KOI8-R/man8)
	${INSTALL_MAN_DIR} ${DST_MAN_DIR}/ru_RU.KOI8-R/man8
.endif
.if !exists(${DST_MAN_DIR}/ru_SU.KOI8-R)
	${LN} -s ${DST_MAN_DIR}/ru_RU.KOI8-R ${DST_MAN_DIR}/ru_SU.KOI8-R
.endif
	${INSTALL_MAN} man/ru_RU.KOI8-R/ipa.5 man/ru_RU.KOI8-R/ipa.conf.5 ${DST_MAN_DIR}/ru_RU.KOI8-R/man5
	${INSTALL_MAN} man/ru_RU.KOI8-R/ipa.8 man/ru_RU.KOI8-R/ipastat.8 ${DST_MAN_DIR}/ru_RU.KOI8-R/man8
.if !defined(NOPORTDOCS)
	${INSTALL_DATA_DIR} ${DST_EXAMPLE_DIR}
	${INSTALL_DATA} examples/* ${DST_EXAMPLE_DIR}
.endif
.if exists(${DST_RC_DIR})
	${INSTALL_SCRIPT} etc/ipa.sh.sample ${DST_RC_DIR}
.else
	@${ECHO}
	@${ECHO} ">> Can't find directory ${DST_RC_DIR}, the ipa.sh.sample file was not installed (not a problem)."
	@${ECHO}
.endif
.if exists(${DST_ETC_DIR})
	${INSTALL_DATA} etc/ipa.conf.default ${DST_ETC_DIR}
.else
. if exists(${DST_RC_DIR})
	@${ECHO}
. endif
	@${ECHO} ">> Can't find directory ${DST_ETC_DIR}, the ipa.conf.default file was not installed (not a problem)."
	@${ECHO}
.endif
