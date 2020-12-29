BASIC_METRICS = {
    'cpu.usage': {
        's_type': 'rate',
        'unit': 'percent',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    # Idle
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'cpu.idle': {
        's_type': 'delta',
        'unit': 'millisecond',
        'rollup': 'summation',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    # Ready
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'cpu.ready': {
        's_type': 'delta',
        'unit': 'millisecond',
        'rollup': 'summation',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    # Utilization
    # Compatibility: UNKNOWN
    'cpu.utilization': {
        's_type': 'rate',
        'unit': 'percent',
        'rollup': 'average',
        'entity': ['HostSystem']
    },
    # Read latency
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'disk.totalReadLatency': {
        's_type': 'absolute',
        'unit': 'millisecond',
        'rollup': 'average',
        'entity': ['HostSystem']
    },
    # Write latency
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'disk.totalWriteLatency': {
        's_type': 'absolute',
        'unit': 'millisecond',
        'rollup': 'average',
        'entity': ['HostSystem']
    },
    # Usage
    # Compatibility: UNKNOWN
    'disk.usage': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    # Write rate
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'disk.write': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem', 'Datastore']
    },
    # Read rate
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'disk.read': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem', 'Datastore']
    },
    # Granted
    # Compatibility: UNKNOWN
    'mem.granted': {
        's_type': 'absolute',
        'unit': 'kiloBytes',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem', 'ResourcePool']
    },
    # Usage
    # Compatibility: UNKNOWN
    'mem.usage': {
        's_type': 'absolute',
        'unit': 'percent',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    # Total capacity
    # Compatibility: 4.1.0 / 5.0.0
    'mem.totalCapacity': {
        's_type': 'absolute',
        'unit': 'megaBytes',
        'rollup': 'average',
        'entity': ['HostSystem']
    },
    'net.received': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    'net.transmitted': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    # Usage
    # Compatibility: UNKNOWN
    'net.usage': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem']
    },
    # Read rate
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'datastore.read': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem', 'Datastore']
    },
    # Write rate
    # Compatibility: 3.5.0 / 4.0.0 / 4.1.0 / 5.0.0
    'datastore.write': {
        's_type': 'rate',
        'unit': 'kiloBytesPerSecond',
        'rollup': 'average',
        'entity': ['VirtualMachine', 'HostSystem', 'Datastore']
    },
    # Compatibility: 6.0.0
    'sys.uptime': {
        's_type': 'absolute',
        'unit': 'second',
        'rollup': 'latest',
        'entity': ['VirtualMachine', 'HostSystem']
    }
}
