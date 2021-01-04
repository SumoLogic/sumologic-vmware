from __future__ import unicode_literals
from collections import defaultdict
from datetime import datetime, timedelta
from queue import Empty, Queue
from cryptography.fernet import Fernet

import ssl
import time
import traceback
import threading
import sys
import argparse
import json
import socket
import logging

from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl

from basic_metrics import BASIC_METRICS
from thread_pool import Pool
from cache_config import CacheConfig
from objects_queue import ObjectsQueue
from mor_cache import MorCache, MorNotFoundError
from metadata_cache import MetadataCache, MetadataNotFoundError

# vCenter sampling interval
VCENTER_REALTIME_INTERVAL = 20
# Default Threadpool size
DEFAULT_THREADSIZE_POOL = 4
# Simultaneous objects processed by the QueryPref method.
BATCH_MORLIST_SIZE = 50
# Maximum number of objects to collect at once by the propertyCollector.
BATCH_COLLECTOR_SIZE = 500

DEFAULT_COLLECTION_LEVEL = 2

REALTIME_RESOURCES = {'vm', 'host'}

RESOURCE_TYPE_METRICS = [
    vim.VirtualMachine,
    vim.Datacenter,
    vim.HostSystem,
    vim.Datastore
]

RESOURCE_TYPE_NO_METRIC = [
    vim.Datacenter,
    vim.ComputeResource,
    vim.Folder
]


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


class VSphereMetrics():
    """
    Sumo Logic class to get performance metrics from a vCenter server.
    The scripts spits out metrics which are ingested by the sumo logic collector.
    """

    def __init__(self, init_config, instance):

        logfilename = instance.log_file_prefix + "_" + str(datetime.now().timestamp()) + ".log"
        self.logger = logging.getLogger("metrics")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(logfilename)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        self.time_started = time.time()
        self.pool_started = False
        self.except_queue = Queue()

        self.batch_collector_size = BATCH_COLLECTOR_SIZE

        if init_config['CONFIG']['BATCH_MORLIST_SIZE'] is not None:
            self.batch_morlist_size = init_config['CONFIG']['BATCH_MORLIST_SIZE']
        else:
            self.batch_morlist_size = BATCH_MORLIST_SIZE

        if init_config['CONFIG']['DEFAULT_THREADSIZE_POOL'] is not None:
            self.pool_size = init_config['CONFIG']['DEFAULT_THREADSIZE_POOL']
        else:
            self.pool_size = DEFAULT_THREADSIZE_POOL

        self.collection_level = DEFAULT_COLLECTION_LEVEL

        if init_config['CONFIG']['SSL_VERIFY'] is not None:
            self.ssl_verify = init_config['CONFIG']['SSL_VERIFY']
        else:
            self.ssl_verify = 'False'

        if init_config['CONFIG']['SSL_CAPATH'] is not None:
            self.ssl_capath = init_config['CONFIG']['SSL_CAPATH']
        else:
            self.ssl_capath = None

        # Connections to vCenter instances
        self.server_instances = {}
        self.server_instances_lock = threading.RLock()

        # Caching
        self.cache_config = CacheConfig()

        # build up configurations
        # Queue of raw Mor objects to process
        self.mor_objects_queue = ObjectsQueue()

        # Cache of processed managed object reference objects
        self.mor_cache = MorCache()

        # managed entity raw view
        self.registry = {}

        # Metrics metadata, for each instance keeps the mapping: perfCounterKey -> {name, group, description}
        self.metadata_cache = MetadataCache()

    def prepareQueryTimeRange(self, tsFileName):

        endTime = datetime.strptime(str(datetime.now()), '%Y-%m-%d %H:%M:%S.%f')
        beginTime = endTime - timedelta(days=1)

        try:
            with open(tsFileName, 'r') as timestampFile:
                for line in timestampFile:
                    beginTime = datetime.strptime(line, '%Y-%m-%d %H:%M:%S.%f')
                    break
        except Exception as e:
            self.logger.info('Time log not found, will get metrics 1 day back.' + str(e) + '\n' )

        return beginTime, endTime

    def updateLastReadTime(self, lastReadTime, tsFileName):
            timestampFile = open(tsFileName, 'w+')
            timestampFile.write(str(lastReadTime))
            timestampFile.close()

    def start_pool(self):
        self.logger.info("Starting Thread Pool\n")
        self.pool = Pool(self.pool_size)
        self.pool_started = True
        self.logger.info("Pool Size:::" + str(self.pool_size) + "\n")

    def stop_pool(self):
        self.logger.info("Stopping Thread Pool\n")
        if self.pool_started:
            self.pool.terminate()
            self.pool.join()
            assert self.pool.get_nworkers() == 0
            self.pool_started = False

    def _instance_key(self, instance):
        i_key = instance.host
        if i_key is None:
            self.logger.critical("Must define a unique 'hostname' per vCenter instance\n")
            sys.exit("Must define a unique 'hostname' per vCenter instance")
        return i_key

    def _connect_to_server(self, instance):
        # Determine ssl configs and generate an appropriate ssl context object
        if self.ssl_verify is not None:
            ssl_verify = self.ssl_verify

        if self.ssl_capath is not None:
            ssl_capath = self.ssl_capath

        if ssl_verify == 'False':
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_NONE
        elif ssl_capath != "":
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(capath=ssl_capath)

        if ssl_verify == 'False' and ssl_capath != "":
            self.logger.info("Incorrect configuration, proceeding with ssl verification disabled.\n")

        password = instance.password

        if instance.pass_encrypted:
            cipher_suite = Fernet(instance.key)
            uncipher_text = (cipher_suite.decrypt(bytes(instance.password, "utf-8")))
            password = bytes(uncipher_text).decode("utf-8") # convert to string

        try:
            server_instance = connect.SmartConnect(
                host=instance.host,
                port=instance.port,
                user=instance.user,
                pwd=password,
                sslContext=context if ssl_verify == 'False' or ssl_capath != "" else None
            )
        except Exception as e:
            err_msg = "Connection to {} failed: {}\n".format(instance.host, e)
            self.logger.critical(err_msg)
            sys.exit(err_msg)

        # Check permissions
        try:
            server_instance.CurrentTime()
        except Exception as e:
            err_msg = (
                "Connection established: {}, but the user : {} lacks appropriate permissions.\n"
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
                self.server_instances[i_key].CurrentTime()
            except Exception:
                # Try to reconnect. If the connection is definitely broken, it will raise an exception and exit.
                self.server_instances[i_key] = self._connect_to_server(instance)

            return self.server_instances[i_key]

    def _determine_needed_metrics(self, instance, available_metrics):
        """
        Filter to determine what metrics we want to report.
        """

        i_key = self._instance_key(instance)
        wanted_metrics = []
        # Get only the basic metrics
        for metric in available_metrics:
            counter_id = metric.counterId
            # No cache yet, skip it for now
            if not self.metadata_cache.contains(i_key, counter_id):
                self.logger.info("No metadata found for counter {}, will not collect it\n".format(counter_id))
                continue
            metadata = self.metadata_cache.get_metadata(i_key, counter_id)
            if metadata.get('name') in BASIC_METRICS:
                wanted_metrics.append(metric)

        return wanted_metrics

    def _retrieve_managed_objects_and_attr(self, server_instance):
        resources = RESOURCE_TYPE_METRICS + RESOURCE_TYPE_NO_METRIC

        content = server_instance.content
        view_ref = content.viewManager.CreateContainerView(content.rootFolder, resources, True)

        # See https://code.vmware.com/apis/358/vsphere#/doc/vmodl.query.PropertyCollector.html
        collector = content.propertyCollector

        # Specify root object
        obj_spec = vmodl.query.PropertyCollector.ObjectSpec()
        obj_spec.obj = view_ref
        obj_spec.skip = True

        # Mention the attribute of the root object
        traversal_spec = vmodl.query.PropertyCollector.TraversalSpec()
        traversal_spec.path = "view"
        traversal_spec.skip = False
        traversal_spec.type = view_ref.__class__
        obj_spec.selectSet = [traversal_spec]

        property_specs = []
        # Which attributes we want to retrieve per object
        for resource in resources:
            property_spec = vmodl.query.PropertyCollector.PropertySpec()
            property_spec.type = resource
            property_spec.pathSet = ["name", "parent"]
            if resource == vim.VirtualMachine:
                property_spec.pathSet.append("runtime.powerState")
                property_spec.pathSet.append("runtime.host")
            property_specs.append(property_spec)

        # Create final filter spec
        filter_spec = vmodl.query.PropertyCollector.FilterSpec()
        filter_spec.objectSet = [obj_spec]
        filter_spec.propSet = property_specs

        retr_opts = vmodl.query.PropertyCollector.RetrieveOptions()
        # If batch_collector_size is 0, collect maximum number of objects.
        retr_opts.maxObjects = self.batch_collector_size or None

        # Retrieve the objects and their properties
        res = collector.RetrievePropertiesEx([filter_spec], retr_opts)
        objects = res.objects
        # Results can be paginated
        while res.token is not None:
            res = collector.ContinueRetrievePropertiesEx(res.token)
            objects.extend(res.objects)

        mor_attrs = {}
        error_counter = 0
        for obj in objects:
            if obj.missingSet and error_counter < 10:
                for prop in obj.missingSet:
                    error_counter += 1
                    self.logger.error(
                        "Unable to retrieve property {} for object {}: {}\n".format(prop.path, obj.obj, prop.fault)
                    )
                    if error_counter == 10:
                        self.logger.info("Too many errors during object collection, stop logging\n")
                        break
            mor_attrs[obj.obj] = {prop.name: prop.val for prop in obj.propSet} if obj.propSet else {}

        return mor_attrs

    def _get_all_managed_objects(self, server_instance):
        """
        Determine vCenter infrastructure to find out hosts, virtual machines and
        put them in a queue to be processed asynchronously.
        """
        start = time.time()
        obj_list = defaultdict(list)

        # Objects and their attributes
        all_objects = self._retrieve_managed_objects_and_attr(server_instance)

        # Include rootFolder since it is not explored by the propertyCollector
        rootFolder = server_instance.content.rootFolder
        all_objects[rootFolder] = {"name": rootFolder.name, "parent": None}

        for obj, properties in all_objects.items():
            if (
                any(isinstance(obj, vimtype) for vimtype in RESOURCE_TYPE_METRICS)
            ):
                hostname = properties.get("name", "unknown")

                if isinstance(obj, vim.VirtualMachine):
                    vimtype = vim.VirtualMachine
                    mor_type = "vm"
                    power_state = properties.get("runtime.powerState")
                    if power_state != vim.VirtualMachinePowerState.poweredOn:
                        self.logger.info("Skipping VM in state {}\n".format(power_state))
                        continue
                elif isinstance(obj, vim.HostSystem):
                    vimtype = vim.HostSystem
                    mor_type = "host"
                elif isinstance(obj, vim.Datastore):
                    hostname = None
                    vimtype = vim.Datastore
                    mor_type = "datastore"
                elif isinstance(obj, vim.Datacenter):
                    hostname = None
                    vimtype = vim.Datacenter
                    mor_type = "datacenter"

                obj_list[vimtype].append({
                    "mor_type": mor_type,
                    "mor": obj,
                    "hostname": hostname
                })

        self.logger.info("All objects with attributes cached in {} seconds.\n".format(time.time() - start))
        return obj_list

    def _get_managed_obj_refer_list(self, instance):
        """
        FInd out the Mor objects, determine vcenter, virtual machines, hosts and datacenters
        """
        i_key = self._instance_key(instance)
        self.logger.info("Caching the morlist for vcenter instance " + i_key + "\n")

        # If the queue is not completely empty, don't do anything
        for resource_type in RESOURCE_TYPE_METRICS:
            if self.mor_objects_queue.contains(i_key) and self.mor_objects_queue.size(i_key, resource_type):
                last = self.cache_config.get_last(CacheConfig.Morlist, i_key)
                self.logger.info("Skipping morlist collection: the objects queue for the "
                               "resource type '{}' is still being processed "
                               "(latest refresh was {}s ago)\n".format(resource_type, time.time() - last))
                return

        server_instance = self._get_server_instance(instance)
        all_objs = self._get_all_managed_objects(server_instance)
        self.mor_objects_queue.fill(i_key, dict(all_objs))

        self.cache_config.set_last(CacheConfig.Morlist, i_key, time.time())

    def _process_managed_objects_queue(self, instance):
        """
        Retrieves `batch_morlist_size` items from the mor objects queue to fill the Mor cache.
        """
        i_key = self._instance_key(instance)
        self.mor_cache.init_instance(i_key)
        if not self.mor_objects_queue.contains(i_key):
            self.logger.info("Objects queue is not initialized yet for instance {}, skipping processing\n".format(i_key))
            return

        for resource_type in RESOURCE_TYPE_METRICS:
            # If batch size is set to 0, process everything at once
            batch_size = self.batch_morlist_size or self.mor_objects_queue.size(i_key, resource_type)
            while self.mor_objects_queue.size(i_key, resource_type):
                query_specs = []
                for _ in range(batch_size):
                    mor = self.mor_objects_queue.pop(i_key, resource_type)
                    if mor is None:
                        self.logger.info("No more objects of type '{}' left in the queue\n".format(resource_type))
                        break

                    mor_name = str(mor['mor'])
                    mor['interval'] = VCENTER_REALTIME_INTERVAL if mor['mor_type'] in REALTIME_RESOURCES else None
                    # Always update the cache to account for Mors that might have changed parent
                    # in the meantime (e.g. a migrated VM).
                    self.mor_cache.set_mor(i_key, mor_name, mor)

                    # Only do this for non real-time resources i.e. datacenter and datastores
                    # For hosts and VMs, we can rely on a precomputed list of metrics
                    if mor["mor_type"] not in REALTIME_RESOURCES:
                        query_spec = vim.PerformanceManager.QuerySpec()
                        query_spec.entity = mor["mor"]
                        query_spec.intervalId = mor["interval"]
                        query_spec.maxSample = 1
                        query_specs.append(query_spec)

                # Schedule jobs for non realtime resources only.
                if query_specs:
                    i_key = self._instance_key(instance)
                    server_instance = self._get_server_instance(instance)
                    perfManager = server_instance.content.perfManager

                    res = perfManager.QueryPerf(query_specs)
                    for mor_perfs in res:
                        mor_name = str(mor_perfs.entity)
                        available_metrics = [value.id for value in mor_perfs.value]
                        try:

                            self.mor_cache.set_metrics(i_key, mor_name, self._determine_needed_metrics(instance, available_metrics))
                        except MorNotFoundError:
                            self.logger.info("Object '{}' is missing from the cache, skipping.\n".format(mor_name))
                            continue

    def _get_vcenter_metrics_metadata(self, instance):
        """
        Find out all the performance counters metadata meaning name/group/description...
        """

        i_key = self._instance_key(instance)
        self.metadata_cache.init_instance(i_key)
        self.logger.info("Warming metrics metadata cache for instance {}\n".format(i_key))
        server_instance = self._get_server_instance(instance)
        perfManager = server_instance.content.perfManager

        new_metadata = {}
        metric_ids = []
        for counter in perfManager.QueryPerfCounterByLevel(self.collection_level):
            metric_name = self.format_metric_name(counter)
            new_metadata[counter.key] = {
                "name": metric_name,
                "unit": counter.unitInfo.key
            }
            # Build the list of metrics we will want to collect
            if metric_name in BASIC_METRICS:
                metric_ids.append(vim.PerformanceManager.MetricId(counterId=counter.key, instance="*"))

        self.logger.info("Finished metadata collection for instance {}\n".format(i_key))
        # Reset metadata
        self.metadata_cache.set_metadata(i_key, new_metadata)

        self.metadata_cache.set_metric_ids(i_key, metric_ids)

        self.cache_config.set_last(CacheConfig.Metadata, i_key, time.time())

    def format_metric_name(self, counter):
        return "{}.{}".format(counter.groupInfo.key, counter.nameInfo.key)

    def _transform_value(self, instance, counter_id, value):
        """ Given the counter_id, look up for the metrics metadata to check the vsphere
        type of the counter and apply pre-reporting transformation if needed.
        """
        i_key = self._instance_key(instance)
        try:
            metadata = self.metadata_cache.get_metadata(i_key, counter_id)
            if metadata["unit"] == "percent":
                return float(value) / 100
        except MetadataNotFoundError:
            pass

        # Defaults to return the value without transformation
        return value

    @trace_method
    def _collect_vcenter_metrics_async(self, instance, query_specs):
        """
        This procedure collects the metrics listed in the morlist for one MOR
        """
        # Prepare socket to send
        targetSocket = None
        try:
            targetSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as err:
            self.logger.critical(" Socket creation failed with error %s" % (err))
            return

        try:
            # connecting to the server
            targetSocket.connect((instance.target, int(instance.targetPort)))
        except socket.error as err:
            self.logger.critical("The socket failed to connect to server%s" % (err))
            return

        i_key = self._instance_key(instance)
        server_instance = self._get_server_instance(instance)
        perfManager = server_instance.content.perfManager
        results = perfManager.QueryPerf(query_specs)

        if results:

            for mor_perfs in results:
                mor_name = str(mor_perfs.entity)
                try:
                    mor = self.mor_cache.get_mor(i_key, mor_name)
                except MorNotFoundError:
                    self.logger.info("Trying to get metrics from object %s deleted from the cache, skipping. ", mor_name)
                    continue

                for result in mor_perfs.value:
                    output_string = ""
                    counter_id = result.id.counterId
                    if not self.metadata_cache.contains(i_key, counter_id):
                        self.logger.info(
                            "Skipping value for counter {}, because there is no metadata about it".format(counter_id)
                        )
                        continue

                    # Metric types are absolute, delta, and rate
                    metric_name = self.metadata_cache.get_metadata(i_key, result.id.counterId).get('name')
                    if not result.value:
                        self.logger.info("Skipping `{}` metric because the value is empty".format(metric_name))
                        continue

                    value = self._transform_value(instance, result.id.counterId, result.value[0])

                    counter_full = (metric_name.split("."))
                    if len(counter_full) == 2:
                        output_string = output_string + "metric=" + counter_full[0] + "_" + counter_full[1]
                    elif len(counter_full) == 3:
                        output_string = output_string + "metric=" + counter_full[0] + "_" + counter_full[1] + "_" + counter_full[2]
                    else:
                        continue

                    date_time = mor_perfs.sampleInfo[0].timestamp
                    epoch = str(date_time.timestamp()).split('.')[0]
                    output_string = output_string + " type=" + mor['mor_type'] + " hostname=" + str(mor['hostname']).replace(" ", "_") + " vcenter=" + instance.host + "  " + str(value) + " " + str(epoch) + "\n"
                    if targetSocket is not None:
                        try:
                            targetSocket.send(output_string.encode())
                        except Exception:
                            # Prepare socket to send
                            targetSocket = None
                            try:
                                targetSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            except socket.error as err:
                                self.logger.critical(" Socket creation failed with error %s" % (err))
                                return

                            try:
                                # connecting to the server
                                targetSocket.connect((instance.target, int(instance.targetPort)))
                                targetSocket.send(output_string.encode())
                            except socket.error as err:
                                self.logger.critical("The socket failed to connect to server%s" % (err))
                                return


        if targetSocket is not None:
            targetSocket.close()
        return

    def collect_vcenter_metrics(self, instance):
        """
        Calls asynchronously _collect_vcenter_metrics_async on all objects.
        """
        i_key = self._instance_key(instance)
        if not self.mor_cache.contains(i_key):
            self.logger.info("Not collecting metrics for instance '{}'.\n".format(i_key))
            return

        vm_count = 0

        n_mors = self.mor_cache.instance_size(i_key)
        if not n_mors:
            return

        self.logger.info("Collecting metrics for {} managed objects\n".format(n_mors))

        # Request metrics for several objects at once. We can limit the number of objects with batch_size
        # If batch_size is 0, process everything at once
        beginTime, endTime = self.prepareQueryTimeRange(instance.tsFileName)

        batch_size = self.batch_morlist_size or n_mors
        for batch in self.mor_cache.mors_batch(i_key, batch_size):
            query_specs = []
            for mor_name, mor in batch.items():

                if mor['mor_type'] not in REALTIME_RESOURCES and ('metrics' not in mor or not mor['metrics']):
                    continue
                if mor['mor_type'] == 'vm':
                    vm_count += 1
                query_spec = vim.PerformanceManager.QuerySpec()
                query_spec.entity = mor["mor"]
                query_spec.intervalId = mor["interval"]
                query_spec.maxSample = 1
                query_spec.startTime = beginTime
                query_spec.endTime = endTime
                if mor['mor_type'] in REALTIME_RESOURCES:
                    query_spec.metricId = self.metadata_cache.get_metric_ids(i_key)
                else:
                    query_spec.metricId = mor["metrics"]
                query_specs.append(query_spec)

            if query_specs:
                self.pool.apply_async(self._collect_vcenter_metrics_async, args=(instance, query_specs))
        self.updateLastReadTime(endTime, instance.tsFileName)
        self.logger.info('VM Count::' + str(vm_count) + '\n')

    def get_metrics(self, instance):

        if not self.pool_started:
            self.start_pool()

        self.logger.info('Queue Size::' + str(self.pool._workq.qsize()) + "\n")
        self._get_vcenter_metrics_metadata(instance)

        self._get_managed_obj_refer_list(instance)

        self._process_managed_objects_queue(instance)

        self.collect_vcenter_metrics(instance)

        thread_crashed = False
        try:
            while True:
                self.except_queue.get_nowait()
                thread_crashed = True
        except Empty:
            pass

        if thread_crashed:
            self.stop_pool()
            self.logger.critical("A thread in the pool crashed, check the logs\n")
            sys.exit("A thread in the pool crashed, check the logs")

        while True:
            if self.pool._workq.qsize() == 0:
                self.stop_pool()
                self.logger.info("Process complete.\n")
                sys.exit("Process complete.")


def setup_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--host',
                        required=True,
                        action='store',
                        help='Remote vCenter Server IP to connect to')

    parser.add_argument('-o', '--port',
                        required=False,
                        action='store',
                        help="Remote vCenter Server port to use, default 443"
                        , default=443)

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
                        required=True,
                        action='store',
                        help='Target syslog server.')

    parser.add_argument('-to', '--targetPort',
                        required=False,
                        action='store',
                        help="Target port to use, default 2003", default=2003)

    parser.add_argument('-cf', '--config_file',
                        required=True,
                        action='store',
                        help='Configuration File.')

    parser.add_argument('-ts', '--tsFileName',
                        required=False,
                        action='store',
                        help='Timestamp File', default='.timelog_metrics')

    parser.add_argument('-l', '--log_file_prefix',
                        required=False,
                        action='store',
                        help='Log File.', default='vsphere_metrics_')

    args = parser.parse_args()

    if args.pass_encrypted and args.key is None:
        print("Key is required if the password is encrypted")
        sys.exit("Key is required if the password is encrypted")

    return args


def main():
    args = setup_args()
    try:
        with open(args.config_file, 'r') as f:
            config = json.load(f)
    except Exception as e:
            print("Unable to open %s::%s" % (args.config_file, e))
            sys.exit("Unable to open %s::%s" % (args.config_file, e))

    vSphereMetrics = VSphereMetrics(config, args)
    vSphereMetrics.get_metrics(args)


if __name__ == '__main__':
    main()
