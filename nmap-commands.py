#!/usr/bin/env python3

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.objects import NmapHost
import time

# A collection of nmap command lines with various options

def read_scan(data):
    print(data.progress)
    #print(data.state)
    #print(data.tasks)



# Runs a ping scan against the provided hosts or host
def ping_scan(host):

    proc = NmapProcess(host, options='-sn', event_callback=read_scan)
    proc.run()
    #return proc()

# The literal default nmap scan, checking to see that the host is up and
# getting a list of open tcp ports
def default_scan(host):

    proc = NmapProcess(host, options='-sT', event_callback=read_scan)
    proc.run()
    report = NmapParser.parse(proc.stdout)
    return report.hosts[0].get_dict()

def service_scan(host):

    proc = NmapProcess(host, options='-sV', event_callback=read_scan)
    proc.run()
    report = NmapParser.parse(proc.stdout)
    return report.hosts[0].get_dict()



host = default_scan("nmap.scanme.org")
host2 = service_scan("nmap.scanme.org")


print(host)
print(host2)

print(host.diff(host2))
