#!/bin/bash
SCRIPT_PATH=/var/log/vmware

python3 $SCRIPT_PATH/esx_perf_metrics_6_5.py -s <vcenter server> -t <suko streaming metrics host> -to <target port> -u <username> -p <password> -cf $SCRIPT_PATH/sumo.json

# Example 1: Using metrics streaming soure and specific log directory with a specific log file prefix.
# python3 $SCRIPT_PATH/esx_perf_metrics_6_5.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -p sumoadmin -cf $SCRIPT_PATH/sumo.json -l /var/log/vmware/log/metrics


# Example 2: Using specific log directory with a specific log file prefix and encrypted Password.
# python3 $SCRIPT_PATH/esx_perf_metrics_6_5.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -cf $SCRIPT_PATH/sumo.json -l /var/log/vmware/log/vsphere_metrics -pK 'xgb8NJ3ZYPJbzX6vWHySZbLd73bKWPsGMKoSnry7hL4=' -p 'gAAAAABb6asvlRfxEj_ZQTKOyrqnGNMbfo_kpxrqv4DCO6TorS4FmKFzrepe0_xtiMT67ZT6OOf5bfrVZXNnUDFNlwPWrpFSfg==' -pE True

# Example 3: In a case where the cron script run is taking too long because of large infrastructure, following code can be used to continuosly run the script and stream metrics.
# MAKE SURE THAT PIDFILE VARIABLE IN BELOW SCRIPT IS DIFFERENT FOR EACH VCENTER AND DIFFERENT FOR EVENTS AND METRICS.
# Set the CRON expression as * * * * * and use below script.
# SCRIPT_PATH=/var/log/vmware
# PIDFILE=$SCRIPT_PATH/vcenter_server1_metrics.pid
# if [ -f $PIDFILE ]
# then
#   PID=$(cat $PIDFILE)
#   ps -p $PID > /dev/null 2>&1
#   if [ $? -eq 0 ]
#   then
#     echo "Process already running"
#     exit 1
#   else
#     ## Process not found assume not running
#     echo $$ > $PIDFILE
#       python3 $SCRIPT_PATH/esx_perf_metrics_6_5.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -p sumoadmin -cf $SCRIPT_PATH/sumo.json -l /var/log/vmware/log/metrics
#   if [ $? -ne 0 ]
#     then
#       echo "Could not create PID file"
#       exit 1
#     fi
#   fi
# else
#   echo $$ > $PIDFILE
#     python3 $SCRIPT_PATH/esx_perf_metrics_6_5.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -p sumoadmin -cf $SCRIPT_PATH/sumo.json -l /var/log/vmware/log/metrics
#   if [ $? -ne 0 ]
#   then
#     echo "Could not create PID file"
#     exit 1
#   fi
# fi
#
# rm $PIDFILE
