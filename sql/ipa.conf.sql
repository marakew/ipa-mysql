#
# Default configuration file for ipa(8).
# @(#)$Id: ipa.conf.default,v 1.6 2002/12/19 18:56:05 simon Exp $
#

global {

#
# It's *recommended* to set ``maxchunk'' parameter in the ``global''
# section or in the ``rule'' sections, there isn't default value for it.
# See the ipa.conf(5) manual page for more information about its value.
#

maxchunk = 1G
#update_db_time = 5m
update_db_time = 1m

       sql_name = ipa
       sql_user = ipauser
       sql_pswd = ipauser
       sql_host = localhost
       sql_port = 3306

#
}

rule	kent_in	{
ipfw	=	1002
info	=	Down Load from Net
row	=	in
who	=	kent
}

rule	kent_out {
ipfw	=	1003
info	=	Upload to Net
row	=	out
who	=	kent
}

