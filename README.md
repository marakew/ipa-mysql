Project discontinue since 2007 year

patched IPA daemon for mysql accounting with managing web interface admin/user

<img width="100%" src="https://github.com/marakew/ipa-mysql/blob/master/img/luser.jpg">

------------------


			IPA - IP Accounting Software


IPA - What is it?
=================

   IPA is a highly configurable IP accounting software.  It allows to
make IP accounting (network accounting) based on FreeBSD IPv4/v6 Firewall
(IPFW2 as well) rules, OpenBSD Packet Filter and/or IP Filter accounting
rules on FreeBSD, NetBSD and OpenBSD.

   It is not required to be run from the cron(8) or any other periodical
process.  IPA(8) can be run in foreground or background and reads all necessary
accounting information directly from the kernel memory or from the special
devices.  It does not run extra programs (such as ipfw(8), ipfstat(8) or
pfctl(8)) and parse their output.

   It has flexible configuration file with many sections and options.
It is possible to make IP accounting during specified period of week,
accounting per some time intervals, etc.

   IPA(8) operates with customized accounting rules.  Accounting rules
are described in the configuration file.  Each accounting rule can summarize
or subtract counters from FreeBSD IPv4/v6 Firewall, OpenBSD Packet Filter
and/or IP Filter accounting rules.  Each accounting rule can be protected by
the "db_group" parameter and there is special viewer IPASTAT(8), which
should be used to access IP accounting database.  IPASTAT(8) outputs needed
information in pretty text tables, it has many options and it is easy to
analyse outputed accounting information.

   Limits (or quotas) are supported and there can be many limits for one
accounting rule.  "Limit" sections in the accounting rule are not just "limits"
or "quotas", because with each limit can be used so called events, which
allow to escape from external scripts (read more documentation on the
ipa.conf(5) manual page).

   IPA(8) can operate with such time interval as "end of day", "end of week",
"end of month", etc.  As well it can operate with months, days, hours, etc.
IPA(8) works with local time and does not just add some seconds to current
time, instead it calculates time based on settings for current time zone.

   Many other features are supported.

   IPA has been tested and run on following systems with the default
FreeBSD IPv4/v6 Firewall (including IPFW2), default OpenBSD Packet Filter
and default IP Filter version (by the author):

* FreeBSD/i386 3.3, 3.4, 4.0-4.8, 5.0, 5.1
* NetBSD/i386 1.5, 1.5.1, 1.6
* OpenBSD/i386 2.7, 2.9, 3.0-3.2

Download
========

   The latest version of IPA can be found on following sites:

* http://ipa-system.sourceforge.net/


How to install IPA?
===================

   It is quite easy to build and install it.  But you should spend some time
to write a configuration file.  Please read the file "INSTALL".


Documentation
=============

   Complete documentation of IPA is available on its manual pages: ipa(8),
ipastat(8), ipa.conf(5) and ipa(5). All manual pages are also translated
to Russian (setup you locale to ru_RU.KOI8-R or ru_SU.KOI8-R).  Also you
should read documentation for FreeBSD IPv4/v6 Firewall, OpenBSD Packet
Filter and/or IP Filter, if you did not read it before.


Licensing
=========

   Please see the file "LICENSE".


Bugs/Problems
=============

   If you have a problem with IPA on your operating system, please email
a copy of the file "BugReport" with the details of your setup as required.
If you would like to see some new feature in IPA also email me your ideas,
may be proposed feature will be added to it.


Andrey Simonenko
simon@comsys.ntu-kpi.kiev.ua
