#!/bin/bash
SCRIPT_PATH=/var/log/vmware

python3 $SCRIPT_PATH/events.py -s <vcenter server> -t <syslog host> -to <syslog port> -u <username> -p <password> -f <output_filename_path_and_prefix>

# Example 1: Using a file output, use a local or remote file source in this case.
# python3 $SCRIPT_PATH/events.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -p sumoadmin -f /var/log/vmware/output/vsphere_events

# Example 2: Using syslog and specific log directory with a specific log file prefix. Use a syslog source to ingest the logs.
# python3 $SCRIPT_PATH/events.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -p sumoadmin -l /var/log/vmware/log/vsphere_events

# Example 3: Using syslog and specific log directory with a specific log file prefix and encrypted Password. Use a syslog source to ingest the logs.
# python3 $SCRIPT_PATH/events.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -pK 'xgb8NJ3ZYPJbzX6vWHySZbLd73bKWPsGMKoSnry7hL4=' -p 'gAAAAABb6asvlRfxEj_ZQTKOyrqnGNMbfo_kpxrqv4DCO6TorS4FmKFzrepe0_xtiMT67ZT6OOf5bfrVZXNnUDFNlwPWrpFSfg==' -pE True -l /var/log/vmware/log/vsphere_events

# Example 4: In a case where the cron script run is taking too long because of large infrastructure, following code can be used to continuosly run the script and retrieve events.
# MAKE SURE THAT PIDFILE VARIABLE IN BELOW SCRIPT IS DIFFERENT FOR EACH VCENTER AND DIFFERENT FOR EVENTS AND METRICS.
# Set the CRON expression as * * * * * and use below script.
# SCRIPT_PATH=/var/log/vmware
# PIDFILE=$SCRIPT_PATH/vcenter_server1_events.pid
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
#     python3 $SCRIPT_PATH/events.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -p sumoadmin -f /var/log/vmware/output/vsphere_events
#     if [ $? -ne 0 ]
#     then
#       echo "Could not create PID file"
#       exit 1
#     fi
#   fi
# else
#   echo $$ > $PIDFILE
#     python3 $SCRIPT_PATH/events.py -s 192.168.124.29 -t sumologic_host -to sumologic_host_port -u sumoadmin -p sumoadmin -f /var/log/vmware/output/vsphere_events
#   if [ $? -ne 0 ]
#   then
#     echo "Could not create PID file"
#     exit 1
#   fi
# fi
#
# rm $PIDFILE
