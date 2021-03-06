import threading


class ObjectsQueue:
    """
    Implements a queue to store Mor objects of any type for each instance.
    """
    def __init__(self):
        self._objects_queue = {}
        self._objects_queue_lock = threading.RLock()

    def fill(self, key, mor_dict):
        """
        Set a dict mapping (resouce_type --> objects[]) for a given key
        """
        with self._objects_queue_lock:
            self._objects_queue[key] = mor_dict

    def contains(self, key):
        with self._objects_queue_lock:
            return key in self._objects_queue

    def size(self, key, resource_type):
        """
        Return the size of the queue for a given key and resource type.
        """
        with self._objects_queue_lock:
            return len(self._objects_queue[key].get(resource_type, []))

    def pop(self, key, resource_type):
        """
        Extract an object from the list.
        If the list is empty, method will return None
        """
        with self._objects_queue_lock:
            objects = self._objects_queue[key].get(resource_type, [])
            return objects.pop() if objects else None
