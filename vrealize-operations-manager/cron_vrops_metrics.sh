#!/bin/bash
SCRIPT_PATH=/var/log/vmware

python $SCRIPT_PATH/sumologic-vrops-metric-collection.py --server <vrops server> --target <connector streaming metrics host> --targetPort <target port> --user <vrops username> --password <vrops password>

# Example
# python $SCRIPT_PATH/sumologic-vrops-metric-collection.py --server 192.168.124.29 --target vropshost --targetPort 2003 --user vropsadmin --password vropsadmin --log_file_prefix /var/log/vmware/log/metrics
