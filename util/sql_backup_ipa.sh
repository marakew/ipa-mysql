#!/bin/sh
# every day backup
# 0 1 * * * /usr/local/sbin/sql_backup.sh

date=`date "+%Y%m%d"`
db="ipa"
dbdir="/var/backups/ipa"

if [ ! -d ${dbdir} ]; then
	mkdir ${dbdir}
fi

/usr/local/bin/mysqldump --databases ${db} | gzip -c > ${dbdir}/${db}.${date}.gz

