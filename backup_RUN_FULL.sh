rm -rf /oracle/backup_rman/FULL
mkdir /oracle/backup_rman/FULL
#export ORACLE_SID=nmd
#export ORACLE_HOME=/oracle/NMD/12102
#export PATH=/oracle/NMD/12102/bin
rman target / @/oracle/FULL_BACKUP.SQL  LOG /oracle/backup_rman/FULL/rmanlog_%RANDOM%.log

