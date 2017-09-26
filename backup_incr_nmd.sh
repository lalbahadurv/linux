ORACLE_BASE=/oracle/NMD
ORACLE_HOME=/oracle/NMD/12102
ORACLE_SID=NMD
PATH=$ORACLE_HOME/bin:/bin:/usr/bin:/usr/ccs/bin:/usr/sbin:/usr/local/sbin:/sbin:.
SHLIB_PATH=$ORACLE_HOME/lib
LD_LIBRARY_PATH=$ORACLE_HOME/lib:/lib:/usr/lib:.
export ORACLE_BASE
export ORACLE_HOME
export ORACLE_SID
export PATH
export SHLIB_PATH
export LD_LIBRARY_PATH

rm /oracle/RMAN_BACKUP/BACKUP/ORA/DEVQA/NMD/INCR/*
rman target / @/oracle/scripts/incr_backup.sql LOG /oracle/RMAN_BACKUP/BACKUP/ORA/DEVQA/NMD/INCR/INCR_$(date +\%Y\%m\%d_\%H\%M).log
cd /oracle/RMAN_BACKUP/BACKUP_HISTORY/ORA/DEVQA/NMD/INCR 
tar -cvf RMAN_$(date +\%Y\%m\%d_\%H_\%M).tar.gz /oracle/RMAN_BACKUP/BACKUP/ORA/DEVQA/NMD/INCR/*
find /oracle/RMAN_BACKUP/BACKUP_HISTORY/ORA/DEVQA/NMD/INCR -mtime +8 -name "RMAN_*.tar.gz" -print -exec rm {} \;

