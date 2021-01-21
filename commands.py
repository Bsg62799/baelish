#!/usr/bin/env python3

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.objects import NmapHost
import time
import os
import sys

# A collection of nmap command lines with various options and functions


# Runs a ping scan against the provided hosts or host
def ping_scan(host):

    # add hosts that are up to a list to return
    return_hosts = []

    for target in host:
        ret = os.system("ping -c 3 -W 3 " + target + " > /dev/null")
        if ret == 0:
            return_hosts.append(target)


    return return_hosts



# The literal default nmap scan, checking to see that the host is up and
# getting a list of open tcp ports
def default_scan(host,path):

    proc = NmapProcess(host, options='-Pn -oN ' + path + '.txt -oX ' + path + '.xml', safe_mode=False)
    proc.run()
    report = NmapParser.parse_fromfile(path + '.xml')
    return report.hosts[0].get_dict()

def all_scan(host, path):

    proc = NmapProcess(host, options='-A --version-all -p- -oN ' + path + '.txt -oX ' + path + '.xml', safe_mode=False)
    proc.sudo_run()
    report = NmapParser.parse_fromfile(path + '.xml')
    return report.hosts[0].get_dict()
