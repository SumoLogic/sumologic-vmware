#!/usr/bin/env python
"""
Sumo Logic Script for extracting events from VCenter/ESXI Server
"""
import re
import sys
import datetime
import socket
import argparse
import atexit
import ssl
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
from cryptography.fernet import Fernet
from vmware_constants import event_type_list


def prepareQueryTimeRange(tsFileName, optBeginTime, optEndTime, logfile, logPrefix):

    endTime = datetime.datetime.now()
    beginTime = endTime - datetime.timedelta(days=1)
    if optEndTime is not None:
        endTime = datetime.datetime.strptime(optEndTime, '%Y-%m-%d %H:%M:%S.%f%z')

    if optBeginTime is not None:
        beginTime = datetime.datetime.strptime(optBeginTime, '%Y-%m-%d %H:%M:%S.%f%z')
    else:
        try:
            with open(tsFileName, 'r') as timestampFile:
                for line in timestampFile:
                    beginTime = datetime.datetime.strptime(line, '%Y-%m-%d %H:%M:%S.%f%z')
                    break
        except Exception:
            logfile.write(logPrefix + 'Time log not found, will get events 1 day back.\n')

    return beginTime, endTime


def updateLastReadTime(lastReadTime, tsFileName):
    timestampFile = open(tsFileName, 'w+')
    timestampFile.write(str(lastReadTime))
    timestampFile.close()


def setup_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--server',
                        required=True,
                        action='store',
                        help='Remote vCenter Server to connect to')

    parser.add_argument('-o', '--port',
                        required=False,
                        action='store',
                        help="Remote vCenter Server port to use, default 443", default=443)

    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='User name to use when connecting to server')

    parser.add_argument('-p', '--password',
                        required=True,
                        action='store',
                        help='Password to use when connecting to server')

    parser.add_argument('-f', '--file',
                        required=False,
                        action='store',
                        help='Output File Prefix.')

    parser.add_argument('-ts', '--timestampFile',
                        required=False,
                        action='store',
                        help='Timestamp File.', default='.timelog_events')

    parser.add_argument('-t', '--target',
                        required=False,
                        action='store',
                        help='Target syslog server.')

    parser.add_argument('-to', '--targetPort',
                        required=False,
                        action='store',
                        help="Target port to use, default 514", default=514)

    parser.add_argument('-bT', '--optBeginTime',
                        required=False,
                        action='store',
                        help='Begin Time to query for the events.')

    parser.add_argument('-eT', '--optEndTime',
                        required=False,
                        action='store',
                        help='End Time to query for the events.')

    parser.add_argument('-sV', '--ssl_verify',
                        required=False,
                        action='store',
                        help='Use SSL for connection.', default=False)

    parser.add_argument('-sC', '--ssl_capath',
                        required=False,
                        action='store',
                        help='SSL cert for connection.', default=None)

    parser.add_argument('-l', '--log_file_prefix',
                        required=False,
                        action='store',
                        help='Log File.', default='vsphere_events_')

    parser.add_argument('-pE', '--pass_encrypted',
                        required=False,
                        action='store',
                        help='Is the password encrypted?', default=False)

    parser.add_argument('-pK', '--key',
                        required=False,
                        action='store',
                        help='Encryption Key', default=False)

    args = parser.parse_args()

    if args.target is None and args.file is None:
        sys.exit("Target syslog server or file is required.")

    if args.pass_encrypted and args.key is None:
        sys.exit("Key is required if the password is encrypted.")

    args = parser.parse_args()

    return args


def main():
    args = setup_args()
    logPrefix = "server: " + args.server + " >>> "

    try:
        logfilename = args.log_file_prefix + "_" + str(datetime.datetime.now().timestamp()) + ".log"
        logfile = open(logfilename, 'w+')
    except Exception as e:
        sys.exit(logPrefix + "Unable to open logfile:: Error:: %s" % (e))

    outputFile = None
    if args.file == "-":
        outputFile = sys.stdout
    elif args.file is not None:
        try:
            outfilename = args.file + "_" + str(datetime.datetime.now().timestamp()) + ".evt.out"
            outputFile = open(outfilename, 'w+')
        except Exception as e:
            logfile.write(logPrefix + "Unable to open %s\n" % args.file)
            sys.exit(logPrefix + "Unable to open output file %s:: Error:: %s" % (args.file, e))

    # Prepare socket to send
    targetSocket = None
    if args.target is not None:
        try:
            targetSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as err:
            logfile.write(logPrefix + " Socket creation failed with error %s\n" % (err))
            sys.exit(logPrefix + " Socket creation failed with error %s" % (err))

        try:
            # connecting to the server
            targetSocket.connect((args.target, int(args.targetPort)))
        except socket.error as err:
            logfile.write(logPrefix + "Target server connection failed with error %s\n" % (err))
            sys.exit(logPrefix + "Target server connection failed with error %s" % (err))

    #  Prepare time range for query

    beginTime, endTime = prepareQueryTimeRange(args.timestampFile, args.optBeginTime, args.optEndTime, logfile, logPrefix)

    logfile.write(logPrefix + "Begintime:::%s\n" %beginTime)
    logfile.write(logPrefix + "Endtime:::%s\n" %endTime)

    # Check for ssl configs and generate an appropriate ssl context object
    ssl_verify = args.ssl_verify
    ssl_capath = args.ssl_capath

    if not ssl_verify:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE
    elif ssl_capath:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(capath=ssl_capath)

    if not ssl_verify and ssl_capath:
        logfile.write(logPrefix + "Incorrect configuration, proceeding with "
                       "ssl verification disabled.\n")
    password = args.password
    if args.pass_encrypted:
        cipher_suite = Fernet(args.key)
        uncipher_text = (cipher_suite.decrypt(bytes(args.password, "utf-8")))
        password = bytes(uncipher_text).decode("utf-8") # convert to string

    serverConn = SmartConnect(host=args.server,
                           user=args.user,
                           pwd=password,
                           port=args.port,
                           sslContext=context if not ssl_verify or ssl_capath else None)
    atexit.register(Disconnect, serverConn)
    separator = ",,,"
    evtCount = 0
    byTime = vim.event.EventFilterSpec.ByTime(beginTime=beginTime, endTime=endTime)
    filterSpec = vim.event.EventFilterSpec(eventTypeId=event_type_list, time=byTime)
    eventManager = serverConn.content.eventManager
    eventCollector = eventManager.CreateCollectorForEvents(filterSpec)
    eventCollector.RewindCollector()
    aboutInfo = serverConn.content.about
    lastReadTime = None
    while True:
        packetContent = ""
        try:
            eventsArray = eventCollector.ReadNextEvents(maxCount=400)
            if len(eventsArray) == 0:
                break
            for event in eventsArray:
                evtCount += 1
                if hasattr(event, 'createdTime') and getattr(event, 'createdTime') is not None:
                    if event.createdTime.strftime('%Y-%m-%d %H:%M:%S.%f%z') == beginTime:
                        continue
                    packetContent = str(event.createdTime) + " "
                    lastReadTime = event.createdTime.strftime('%Y-%m-%d %H:%M:%S.%f%z')
                if hasattr(event, 'fullFormattedMessage') and getattr(event, 'fullFormattedMessage') is not None:
                    fullMsg = str(getattr(event, 'fullFormattedMessage'))
                    fullMsg = re.sub(r'[^[:ascii:]]+', r'', fullMsg)
                    fullMsg = re.sub(r'[\n]+', r'', fullMsg)
                    packetContent = packetContent + separator + " message=" + fullMsg + separator + "user=" + event.userName
                packetContent = packetContent + separator + "eventType=" + str(type(event))
                if hasattr(event, 'vm') and getattr(event, 'vm') is not None:
                    packetContent = packetContent + separator + "vm=" + event.vm.name
                if hasattr(event, 'host') and getattr(event, 'host') is not None:
                    packetContent = packetContent + separator + "host=" + event.host.name
                if hasattr(event, 'datacenter') and getattr(event, 'datacenter') is not None:
                    packetContent = packetContent + separator + "datacenter=" + event.datacenter.name
                if hasattr(event, 'computeResource') and getattr(event, 'computeResource') is not None:
                    packetContent = packetContent + separator + "computeResource=" + event.computeResource.name
                if hasattr(event, 'changeTag') and getattr(event, 'changeTag') is not None:
                    packetContent = packetContent + separator + "changeTag=" + event.changeTag.name
                if hasattr(event, 'key') and getattr(event, 'key') is not None:
                    packetContent = packetContent + separator + "key=" + str(event.key)
                if hasattr(event, 'chainId') and getattr(event, 'chainId') is not None:
                    packetContent = packetContent + separator + "chainId=" + str(event.chainId)

                if hasattr(event, 'info') and getattr(event, 'info') is not None and getattr(event.info, 'error') is not None:
                    packetContent = packetContent + separator + "error=" + str(event.info.error)

                if hasattr(event, 'vm') and getattr(event, 'vm') is not None:
                    packetContent = packetContent + separator + "vmMoref=" + str(event.vm.vm)

                if hasattr(event, 'datacenter') and getattr(event, 'datacenter') is not None:
                    packetContent = packetContent + separator + "datacenterMoref=" + str(event.datacenter.datacenter)

                if hasattr(aboutInfo, 'instanceUuid') and getattr(aboutInfo, 'instanceUuid') is not None:
                    packetContent = packetContent + separator + "vCenterUUID=" + str(aboutInfo.instanceUuid)
                # Set Dummy Priority to 31 i.e. Debug for System Daemons
                packetContent = "<31>1 " + packetContent + "\n"

                if outputFile is not None:
                    outputFile.write(packetContent)
                if targetSocket is not None:
                    try:
                        targetSocket.send(packetContent.encode())
                    # Prepare socket to send
                    except:
                        targetSocket = None
                        if args.target is not None:
                            try:
                                targetSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            except socket.error as err:
                                logfile.write(logPrefix + " Socket creation failed with error %s\n" % (err))
                                sys.exit(logPrefix + " Socket creation failed with error %s" % (err))

                            try:
                                # connecting to the server
                                targetSocket.connect((args.target, int(args.targetPort)))
                                targetSocket.send(packetContent.encode())
                            except socket.error as err:
                                logfile.write(logPrefix + "Target server connection failed with error %s\n" % (err))
                                sys.exit(logPrefix + "Target server connection failed with error %s" % (err))
        except Exception as e:
            # Ignore failed events for next pass
            logfile.write(logPrefix + "Warning: Unable to fetch Events, skipping for next run.")
            lastReadTime = eventManager.latestEvent.createdTime.strftime('%Y-%m-%d %H:%M:%S.%f%z')
            break

    logfile.write(logPrefix + "%s events collected.\n" % (evtCount))

    if lastReadTime is not None:
        logfile.write(logPrefix + " Updating timelog with %s ...\n" % (lastReadTime))
        updateLastReadTime(lastReadTime, args.timestampFile)
        logfile.write(logPrefix + " Done, exiting.\n")
    elif evtCount != 0:
        logfile.write(logPrefix + "Error: No last read time\n")

    if logfile is not None:
        logfile.close()

    if outputFile is not None:
        outputFile.close()

    if targetSocket is not None:
        targetSocket.close()


if __name__ == '__main__':
    main()
