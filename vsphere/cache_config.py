
import threading
from collections import defaultdict


class CacheConfig:
    """
    CacheConfig is threadsafe and can be used from different workers in the threading pool.
    """
    Morlist = 0
    Metadata = 1

    def __init__(self):
        self._lock = threading.RLock()
        self.clear()

    def _check_type(self, type_):
        if type_ not in (CacheConfig.Morlist, CacheConfig.Metadata):
            raise TypeError("Wrong cache type passed")

    def clear(self):
        """
        Reset the config
        """
        with self._lock:
            self._config = {
                CacheConfig.Morlist: {
                    'last': defaultdict(float),
                    'intl': {},
                },
                CacheConfig.Metadata: {
                    'last': defaultdict(float),
                    'intl': {},
                }
            }

    def set_last(self, type_, key, ts):
        self._check_type(type_)
        with self._lock:
            self._config[type_]['last'][key] = ts

    def get_last(self, type_, key):
        """
        Notice: this will return the defaultdict default value also for keys
        """
        self._check_type(type_)
        with self._lock:
            return self._config[type_]['last'][key]

    def set_interval(self, type_, key, ts):
        self._check_type(type_)
        with self._lock:
            self._config[type_]['intl'][key] = ts

    def get_interval(self, type_, key):
        self._check_type(type_)
        with self._lock:
            return self._config[type_]['intl'].get(key)
