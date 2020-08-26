# !/usr/bin python

"""
# This script extracts metrics from vRealize Operation Center and pushes to a syslog endpoint.
"""
# Importing the Modules

import nagini
import requests
import json
import os
import sys
import base64
import time
import argparse
from datetime import datetime, timedelta
import logging
import socket
import threading
import math
import traceback
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from cryptography.fernet import Fernet
from thread_pool import Pool
from queue import Empty, Queue

# Default Threadpool size
DEFAULT_THREADSIZE_POOL = 4
# Default Simultaneous objects processed by the Nagini get stats method.
BATCH_SIZE = 50
# Default Number of backfill hours to pull data from
BACKFILL_HOURS = 1

def trace_method(method):
    """
    Method to catch asynchronous method failures.
    """
    def wrapper(*args, **kwargs):
        try:
            method(*args, **kwargs)
        except Exception:
            args[0].except_queue.put("A thread crashed:\n" + traceback.format_exc())
            print("A thread crashed:\n", traceback.format_exc())
    return wrapper

class VRopsMetrics():
    """
    Sumo Logic class to get performance metrics from a vRops server.
    The scripts spits out metrics which are ingested by the sumo logic collector.
    """

    def __init__(self, config, instance):
        logfilename = instance.log_file_prefix + "_" + \
            str(datetime.now().timestamp()) + ".log"
        self.logger = logging.getLogger("metrics")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(logfilename)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        self.time_started = time.time()

        self.pool_started = False
        self.except_queue = Queue()

        self.config = config

        if config['BACKFILL_HOURS'] is not None:
            self.backfill_hours = config['BACKFILL_HOURS']
        else:
            self.backfill_hours = BACKFILL_HOURS

        if config['DEFAULT_THREADSIZE_POOL'] is not None:
            self.pool_size = config['DEFAULT_THREADSIZE_POOL']
        else:
            self.pool_size = DEFAULT_THREADSIZE_POOL

        if config['BATCH_SIZE'] is not None:
            self.batch_size = config['BATCH_SIZE']
        else:
            self.batch_size = BATCH_SIZE

        if config['SSL_VERIFY'] is not None:
            self.ssl_verify = config['SSL_VERIFY']
        else:
            self.ssl_verify = 'False'

        if config['SSL_CAPATH'] is not None:
            self.ssl_capath = config['SSL_CAPATH']
        else:
            self.ssl_capath = None

        if config['GET_ALL_METRICS'] is not None:
            self.get_all_metrics = config['GET_ALL_METRICS']
        else:
            self.get_all_metrics = 'False'

        # Connections to vRops instances
        self.server_instances = {}
        self.server_instances_lock = threading.RLock()

    def prepareQueryTimeRange(self, tsFileName):

        beginTime = int(((datetime.utcnow() - timedelta(hours=int(self.backfill_hours))) - datetime(1970, 1, 1)).total_seconds() * 1000)
        endTime = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)

        try:
            with open(tsFileName, 'r') as timestampFile:
                for line in timestampFile:
                    beginTime = line
                    break
        except Exception as e:
            self.logger.info('Time log not found, will get metrics 1 day back.' + str(e) + '\n' )

        return beginTime, endTime

    def updateLastReadTime(self, lastReadTime, tsFileName):
        timestampFile = open(tsFileName, 'w+')
        timestampFile.write(str(lastReadTime))
        timestampFile.close()

    def start_pool(self):
        self.logger.info("Sumo Logic vRops - Starting Thread Pool\n")
        self.pool = Pool(self.pool_size)
        self.pool_started = True
        self.logger.info("Sumo Logic vRops - Pool Size:::" + str(self.pool_size) + "\n")

    def stop_pool(self):
        self.logger.info("Sumo Logic vRops - Stopping Thread Pool\n")
        if self.pool_started:
            self.pool.terminate()
            self.pool.join()
            assert self.pool.get_nworkers() == 0
            self.pool_started = False

    def _instance_key(self, instance):
        i_key = instance.host
        if i_key is None:
            self.stop_pool()
            self.logger.critical("Sumo Logic vRops - Must define a unique 'hostname' per vCenter instance\n")
            sys.exit("Sumo Logic vRops - Must define a unique 'hostname' per vCenter instance")
        return i_key

    def _connect_to_server(self, instance):
        # Determine ssl configs and generate an appropriate ssl context object
        if self.ssl_verify is not None:
            ssl_verify = self.ssl_verify

        if self.ssl_capath is not None:
            ssl_capath = self.ssl_capath

        if ssl_verify == 'False':
            # Disabling the warning sign for self signed certificates. Remove the below line for CA certificates
            self.logger.info("Sumo Logic vRops - SSL Verify is False, disabling warning for self signed certificates.")
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        if ssl_verify == 'False' and ssl_capath != "":
            self.logger.info("Sumo Logic vRops - Incorrect configuration, proceeding with ssl verification disabled.\n")

        password = instance.password

        if instance.pass_encrypted:
            cipher_suite = Fernet(instance.key)
            uncipher_text = (cipher_suite.decrypt(bytes(instance.password, "utf-8")))
            password = bytes(uncipher_text).decode("utf-8") # convert to string

        try:
            if ssl_verify == 'True':
                server_instance = nagini.Nagini(host=instance.host, user_pass=(
                    instance.user, password), verify=True, certs=ssl_capath)
            else:
                server_instance = nagini.Nagini(host=instance.host, user_pass=(
                    instance.user, password), verify=False)

        except Exception as e:
            self.stop_pool()
            err_msg = "Sumo Logic vRops - Connection to {} failed: {}\n".format(instance.host, e)
            self.logger.critical(err_msg)
            sys.exit(err_msg)

        # Check permissions
        try:
            server_instance.get_resources(pageSize=1, page=0)
        except Exception as e:
            self.stop_pool()
            err_msg = (
                "Sumo Logic vRops - Connection established: {}, but the user : {} lacks appropriate permissions. Error : {}\n"
            ).format(instance.host, instance.username, e)
            self.logger.critical(err_msg)
            sys.exit(err_msg)

        return server_instance

    def _get_server_instance(self, instance):
        i_key = self._instance_key(instance)

        with self.server_instances_lock:
            if i_key not in self.server_instances:
                self.server_instances[i_key] = self._connect_to_server(instance)

            # Test connection
            try:
                self.server_instances[i_key].get_resources(pageSize=1, page=0)
            except Exception:
                # Try to reconnect. If the connection is definitely broken, it will raise an exception and exit.
                self.server_instances[i_key] = self._connect_to_server(instance)

            return self.server_instances[i_key]

    # Function to get the metric data
    @trace_method
    def _get_metric_data_async(self, instance, resourceList, key, sampleno, beginTime, endTime):
        try:
            server_instance = self._get_server_instance(instance)
            for resource in resourceList:
                name = resource['identifier']

                # Getting the metric values for the keys of a particular resource
                allvalues = server_instance.get_stats_of_resources(
                    resourceId=name, statKey=key, latestMaxSamples=sampleno, id=name, begin=beginTime, end=endTime)
                targetSocket = None
                if instance.target:
                    try:
                        targetSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    except socket.error as err:
                        self.logger.critical("Sumo Logic vRops - Socket creation failed with error %s" % (err))
                        return

                    try:
                        # connecting to the server
                        targetSocket.connect((instance.target, int(instance.targetPort)))
                    except socket.error as err:
                        self.logger.critical("Sumo Logic vRops - The socket failed to connect to server%s" % (err))
                        return
                if not allvalues["values"]:
                    return
                else:
                    # We have a range of values to store
                    for singlevalue in allvalues["values"][0]["stat-list"]["stat"]:
                        if 'data' in singlevalue and 'timestamps' in singlevalue and 'statKey' in singlevalue:
                            sample = len(singlevalue["data"])
                            for i in range(sample):
                                output_string = ""
                                output_string = "metric=" + (singlevalue["statKey"]["key"]).replace(" ", "_") + " resource_kind=" + \
                                    (resource['resourceKey']['resourceKindKey']).replace(" ", "_") + " adaptor_kind=" + \
                                    (resource['resourceKey']['adapterKindKey']).replace(" ", "_") + " resource_name=" + (resource['resourceKey']['name']).replace(" ", "_") + \
                                    " resource_identifier=" + \
                                    (resource['identifier']).replace(" ", "_") + "  " + str(singlevalue["data"][i]) + \
                                        " " + str(singlevalue["timestamps"][i]) + "\n"
                                if targetSocket is not None:
                                    try:
                                        body_bytes = output_string.encode('ascii')
                                        targetSocket.send(body_bytes)

                                    except Exception:
                                        # Prepare socket to send
                                        targetSocket = None
                                        try:
                                            targetSocket = socket.socket(
                                                socket.AF_INET, socket.SOCK_STREAM)
                                        except socket.error as err:
                                            self.logger.critical(
                                                "Sumo Logic vRops - Sumo Logic vRops - Socket creation failed with error %s" % (err))
                                            return

                                        try:
                                            # connecting to the server
                                            targetSocket.connect(
                                                (instance.target, int(instance.targetPort)))
                                            targetSocket.send(body_bytes)
                                        except socket.error as err:
                                            self.logger.critical(
                                                "Sumo Logic vRops - Sumo Logic vRops - The socket failed to connect to server%s" % (err))
                                            return

            if targetSocket is not None:
                targetSocket.close()

            return
        except Exception:
            self.logger.critical(
                "Sumo Logic vRops - Critical Failure ::: %s" % (traceback.print_exc()))
            return

    def collect_metrics(self, instance):

        # connecting to the vROps server
        self.logger.info("Sumo Logic vRops - Started Metric Collection\n")

        """
        Getting Token

        vrops = nagini.Nagini(host=servername, user_pass=(uid, passwd) )

        serverdata={}
        serverdata["username"] = uid
        serverdata["password"] = passwd
        serverdata["authSource"] = "Local Users"
        databack = vrops.acquire_token(serverdata)

        token = databack["token"]
        validity = databack["validity"]

        # Making further calls
        """

        totalResourceObjects = 0
        totalReportedResources = 0
        totalPages = 0
        resourceList = []
        server_instance = self._get_server_instance(instance)
        beginTime, endTime = self.prepareQueryTimeRange(instance.tsFileName)

        if self.get_all_metrics == 'True':
            # Getting a list of all resources.
            resources = server_instance.get_resources(pageSize=self.batch_size, page=0)
            totalResourceObjects = int(resources['pageInfo']['totalCount'])
            if totalResourceObjects > 0:
                for resource in resources['resourceList']:
                    if resource['resourceStatusStates'][0]['resourceState'] == 'STARTED': # Fetch metrics only for started resources
                        totalReportedResources = totalReportedResources + 1
                        resourceList.append(resource)
                if len(resourceList) > 0:
                    self.pool.apply_async(self._get_metric_data_async, args=(instance,
                        resourceList, None, 1, beginTime, endTime ))

            if totalResourceObjects > self.batch_size:
                totalPages = math.ceil(totalResourceObjects/self.batch_size) # We have already retrieved the 0th page
                for page in range(1, totalPages): # Max value is not included in the loop
                    resourceList = []
                    resources = server_instance.get_resources(pageSize=self.batch_size, page=page)

                    for resource in resources['resourceList']:
                        if resource['resourceStatusStates'][0]['resourceState'] == 'STARTED': # Fetch metrics only for started resources
                            totalReportedResources = totalReportedResources + 1
                            resourceList.append(resource)
                    if len(resourceList) > 0:
                        self.pool.apply_async(self._get_metric_data_async, args=(instance,
                            resourceList, None, 1, beginTime, endTime))

        else:
            # Getting the metric data for all the resources which match the criteria
            for res in self.config['resources']:
                adaptorKindKey = res['adapterKind']
                if adaptorKindKey == "":
                    adaptorKindKey = None
                # Getting the list of Keys for which to collect metrics
                key = []
                resourceList = []
                for i in res['keys']:
                    key.append(i)

                # Getting a list of resources which matches the criteria or resourceKind and adapterKind.
                resources = server_instance.get_resources(resourceKind=res['resourceKind'], adapterKindKey=adaptorKindKey,pageSize=self.batch_size, page=0)

                totalResourceObjects = int(resources['pageInfo']['totalCount'])

                if totalResourceObjects > 0:
                    for resource in resources['resourceList']:
                        if resource['resourceStatusStates'][0]['resourceState'] == 'STARTED': # Fetch metrics only for started resources
                            totalReportedResources = totalReportedResources + 1
                            resourceList.append(resource)
                    if len(resourceList) > 0:
                        self.pool.apply_async(self._get_metric_data_async, args=(instance,
                            resourceList, key, res['sampleno'], beginTime, endTime))
                if totalResourceObjects > self.batch_size:
                    totalPages = math.ceil(totalResourceObjects/self.batch_size) # We have already retrieved the 0th page
                    for page in range(1, totalPages): # Max value is not included in the loop
                        resourceList = []
                        # Getting a list of resources which matches the criteria or resourceKind and adapterKind.
                        resources = server_instance.get_resources(resourceKind=res['resourceKind'], adapterKindKey=adaptorKindKey,pageSize=self.batch_size, page=page)

                        for resource in resources['resourceList']:
                            if resource['resourceStatusStates'][0]['resourceState'] == 'STARTED': # Fetch metrics only for started resources
                                totalReportedResources = totalReportedResources + 1
                                resourceList.append(resource)
                        if len(resourceList) > 0:
                            self.pool.apply_async(self._get_metric_data_async, args=(instance,
                                resourceList, key, res['sampleno'], beginTime, endTime))

        self.logger.info(
                        "Sumo Logic vRops - Total Resources %s. Running Resources %s." % (totalResourceObjects,totalReportedResources))
        return endTime

    def get_metrics(self, instance):

        if not self.pool_started:
            self.start_pool()

        self.logger.info('Sumo Logic vRops - Queue Size::' + str(self.pool._workq.qsize()) + "\n")

        endTime = 0

        try:
            endTime = self.collect_metrics(instance)
        except Exception:
            self.stop_pool()
            self.logger.critical("Sumo Logic vRops - Critical Error::%s" % (traceback.print_exc()))
            sys.exit("Sumo Logic vRops - Critical Error::%s" % (traceback.print_exc()))

        thread_crashed = False
        try:
            while True:
                self.except_queue.get_nowait()
                thread_crashed = True
        except Empty:
            pass

        if thread_crashed:
            self.stop_pool()
            self.logger.critical("Sumo Logic vRops - A thread in the pool crashed, check the logs\n")
            sys.exit("Sumo Logic vRops - A thread in the pool crashed, check the logs")

        while True:
            if self.pool._workq.qsize() == 0:
                self.stop_pool()
                self.updateLastReadTime(endTime, instance.tsFileName)
                self.logger.info("Sumo Logic vRops - Process complete.\n")
                sys.exit("Sumo Logic vRops - Process complete.")


def setup_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--host',
                        required=True,
                        action='store',
                        help='Remote vRops Server IP to connect to')

    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='User name to use when connecting to server')

    parser.add_argument('-p', '--password',
                        required=True,
                        action='store',
                        help='Password to use when connecting to server')

    parser.add_argument('-pE', '--pass_encrypted',
                        required=False,
                        action='store',
                        help='Is the password encrypted?', default=False)

    parser.add_argument('-pK', '--key',
                        required=False,
                        action='store',
                        help='Encryption Key', default=False)

    parser.add_argument('-t', '--target',
                        required=False,
                        action='store',
                        help='Target syslog server.')

    parser.add_argument('-to', '--targetPort',
                        required=False,
                        action='store',
                        help="Target port to use, default 2003", default=2003)

    parser.add_argument('-cf', '--config_file',
                        required=False,
                        action='store',
                        help='Configuration File.', default='config.json')

    parser.add_argument('-ts', '--tsFileName',
                        required=False,
                        action='store',
                        help='Timestamp File', default='.timelog_metrics')

    parser.add_argument('-l', '--log_file_prefix',
                        required=False,
                        action='store',
                        help='Log File.', default='vrops_metrics_')


    args = parser.parse_args()

    if args.pass_encrypted and args.key is None:
        print("Sumo Logic vRops - Key is required if the password is encrypted")
        sys.exit("Sumo Logic vRops - Key is required if the password is encrypted")

    return args


def main():

    args = setup_args()
    try:
        with open(args.config_file, 'r') as f:
            config = json.load(f)
    except Exception as e:
        sys.exit("Sumo Logic vRops - Unable to open %s::%s" % (args.config_file, e))

    vropsMetrics = VRopsMetrics(config, args)
    vropsMetrics.get_metrics(args)


if __name__ == '__main__':
    main()
