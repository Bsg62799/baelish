#!/usr/bin/env python3

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import time

# A collection of nmap command lines with various options

def read_scan(data):
    #print(data.progress)
    #print(data.state)
    #print(data.tasks)
    print(data.etc)



# Runs a ping scan against the provided hosts or host
def ping_scan(host):

    proc = NmapProcess(host, options='-sn', event_callback=read_scan)
    proc.run()
    #return proc()

# The literal default nmap scan, checking to see that the host is up and
# getting a list of open tcp ports
def default_scan(host):

    proc = NmapProcess(host, options='-sT', event_callback=read_scan)
    proc.run_background()
    return proc.rc



proc = default_scan("nmap.scanme.org")

while proc.is_running():

    print('Running!')
    time.sleep(2)
