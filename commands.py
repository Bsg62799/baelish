#!/usr/bin/env python3

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.objects import NmapHost
import time

# A collection of nmap command lines with various options and functions


# Runs a ping scan against the provided hosts or host
def ping_scan(host):
    proc = NmapProcess(host, options='-sn')
    proc.run()
    return NmapParser.parse(proc.stdout)


# The literal default nmap scan, checking to see that the host is up and
# getting a list of open tcp ports
def default_scan(host,path):

    proc = NmapProcess(host, options='-oN ' + path, safe_mode=False)
    proc.run()
    report = NmapParser.parse(proc.stdout)
    return report.hosts[0].get_dict()

def all_scan(host, path):

    proc = NmapProcess(host, options='-A --version-all -p- -oN ' + path, safe_mode=False)
    proc.sudo_run()
    report = NmapParser.parse(proc.stdout)
    return report.hosts[0].get_dict()
