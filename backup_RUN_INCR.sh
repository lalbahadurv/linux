rm -rf /oracle/backup_rman/INCR
mkdir /oracle/backup_rman/INCR
rman target / @/oracle/RMAN_NAS/INCR_BACKUP.SQL LOG /oracle/backup_rman/INCR/rmanlog_%RANDOM%.log

#cd C:\Program Files (x86)\WinRAR
#c:

#rar a -m1 -r -agDD-MMM-YY-HHMM \\10.128.17.15\ORAMSBACKUP\BACKUP_HISTORY\ORA\PRD\PCR\INCR\BACKUP_PCR- \\10.128.17.15\ORAMSBACKUP\BACKUP\ORA\PRD\PCR\INCR
