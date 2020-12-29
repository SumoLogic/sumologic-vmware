
import threading


class MetadataNotFoundError(Exception):
    pass


class MetadataCache:
    """
    For each instance key the cache maps: counter ID --> metric name, unit
    """
    def __init__(self):
        self._metadata = {}
        self._metric_ids = {}
        self._lock = threading.RLock()

    def init_instance(self, key):
        with self._lock:
            if key not in self._metadata:
                self._metadata[key] = {}
                self._metric_ids[key] = []

    def contains(self, key, counter_id):
        """
        Check whether a counter_id is present for a given instance key.
        """
        with self._lock:
            return counter_id in self._metadata[key]

    def set_metadata(self, key, metadata):
        """
        Store the metadata for the given instance key.
        """
        with self._lock:
            self._metadata[key] = metadata

    def set_metric_ids(self, key, metric_ids):
        """
        Store the list of metric IDs we will want to collect for the given instance key
        """
        with self._lock:
            self._metric_ids[key] = metric_ids

    def get_metric_ids(self, key):
        """
        Return the list of metric IDs to collect for the given instance key
        """
        with self._lock:
            return self._metric_ids[key]

    def get_metadata(self, key, counter_id):
        with self._lock:
            metadata = self._metadata[key]
            try:
                return metadata[counter_id]
            except KeyError:
                raise MetadataNotFoundError("No metadata for counter id '{}' found in the cache.".format(counter_id))
