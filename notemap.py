#!/usr/bin/env python3

from cmd import Cmd
from stringcolor import *
import pyfiglet
import importlib
from os import path
import os
from libnmap.parser import NmapParser
from libnmap.diff import NmapDiff
import libnmap
import commands

# globals
stored_hosts = dict()
current_host = ""
project_path = ""
project_name = ""

# Supporting helper methods

# Levies the lipnmap method diff() to compare an existing host object against a new host
# object derived from an nmap scan. This is critical to ensure that, for example, a host that
# was derived from an intense nmap scan the performed service detection against every port is
# not replaced by a host object that simply contains the open ports (default scan result)
def new_info(cur_host, host):

    # init global
    global stored_hosts

    # Check to see if there is any change between the two hosts
    if cur_host.changed(host) > 0:

        # iterate through ports to see if service detection has been done
        for port in cur_host.get_open_ports():
            if cur_host.get_service(port[0]).banner:
                print('\nDisregarding scan. More detailed scan already performed.\n')
                return
        # if service detection hasn't been performed, store the results of this new scan
        # and notify the user of what's been updated
        print("\nUpdated information:")
        for service in NmapDiff(cur_host, host).changed():
            print('- Port ' + str(host.get_service(int(service.split('.')[1])).port) + ': ' + host.get_service(int(service.split('.')[1])).banner)
        print('\n')
        stored_hosts[cur_host.ipv4] = host

# Given a host, prints all known information
def host_info(host_ip):

    # Ensure the host exists
    if not host_ip in stored_hosts.keys():
        print("Host does not exist!")
        return

    # host object
    host = stored_hosts[host_ip]

    # header
    print("\nHost details for " + host_ip + "" \
    "\n-----------------------------------")

    # print scanned ports and services if available
    print("\nOpen TCP Ports:")
    for port in host.get_open_ports():

        # Ensure port is tcp
        if port[1] == 'tcp':
            service = host.get_service(port[0], port[1])
            print(" * Port " + str(port[0]) + " - " + service.service + " - " + service.banner.split("product:")[1].split("extrainfo:")[0])

    # print os information if available
    if host.os_fingerprinted:
        if "SCAN" in host.os_fingerprint:
            print("\nOS: No Match")

        else:
            print("\n" + host.os_fingerprint)
    else:
        print("\nOS: N/A")

# Interactive Shell
class BaelishPrompt(Cmd):

    # Establish a project directory before entering command loop
    def preloop(self):

        # Set the path for the project
        global project_path, current_host, stored_hosts
        response = input(cs("\n------------------------------------------\n" + pyfiglet.figlet_format("NoteMap", font="slant") + \
        "------------------------------------------\n\n" \
        "Welcome to notemap, a tool to aid in handling information for penetration tests" \
        "\nType ? to list available commands" \
        "\nTo get started, enter a new or exisiting project path: ", "cyan"))

        # spacing
        print('')

        # verify that the path exists, or make a new directory
        if not path.isdir(response):
            os.mkdir(response)

        # If the path does exist, load in existing data
        else:

            # Iterate through every dir (host) in the project folder
            for dir in os.listdir(response):

                # If available, load host from an all scan
                if 'nmap-all.xml' in os.listdir(response + '/' + dir):
                    info = NmapParser.parse_fromfile(response + '/' + dir + '/' + 'nmap-all.xml')
                    stored_hosts[dir] = info.hosts[0]

                # Otherwise, load host from a default scan
                elif 'nmap.xml' in os.listdir(response + '/' + dir):
                    info = NmapParser.parse_fromfile(response + '/' + dir + '/' + 'nmap.xml')
                    stored_hosts[dir] = info.hosts[0]

                # Otherwise initailize an empty dict entry
                else:
                    stored_hosts[dir] = dict()


        # store the project path to provide output paths later
        project_path = response

        # Derive the name for the project from the path
        global project_name
        if '/' in project_path:
            dirs = project_path.split('/')
            project_name = dirs[len(dirs) - 1]
        else:
            project_name = project_path

        # update the visual prompt to show project name including the host if only one was found
        if len(os.listdir(response)) == 1:
            current_host = os.listdir(response)[0]
            self.prompt = cs(project_name + '/' + current_host + "> ", "cyan")
        else:
            self.prompt = cs(project_name + ">", "cyan")

    # Currently just breaks the commandloop and ends the program
    def do_exit(self, inp):
        return True

    def help_exit(self):
        print('\nUsage: \'exit\'\n- Exits baelish and saves project files to a directory\n')

    # Allows a user to add a host or set of hosts to a project
    # This runs a ping scan against the host to ensure it is up before adding
    # it to stored_hosts
    def do_host(self, inp):

        # init globals
        global stored_hosts

        # split up provided hostnames or addresses
        hosts = inp.split(' ')

        # run a ping scan against the targets and receive a report
        up_hosts = commands.ping_scan(hosts)

        # display hosts that responded to the scan and add them to global hosts
        for host in up_hosts:

            # Check if the host is already stored so we don't overwrite the entry
            if host not in stored_hosts.keys():
                print("\nHost " + host + " is up, stored as a host!\n")
                stored_hosts[host] = {}

                # if the host is up and unique, create a directory for it
                global project_path
                os.mkdir(project_path + "/" + host)

                # if only one host was given, set current_host
                if len(up_hosts) == 1:
                    global current_host
                    current_host = host
                    self.prompt = cs(project_name + "/" + current_host + "> ", "cyan")

            # Otherwise notify the user
            else:
                print("\nHost " + host + " already stored as a host!\n" )

        # For every host not present in up_hosts, display that they're down to the user
        for host in hosts:
            if host not in up_hosts:
                print("\nHost " + host + " is down!\n")

    def help_host(self):
        print('\nUsage: \'host <ip address> [additional ip addresses]\'' \
        '\n- Runs a ping scan against the provided host(s)' \
        '\n- Prints out whether all host(s) that responded to the ping scan and adds them to the project\n')

    # performs some type of nmap scan against a host or hosts
    def do_scan(self, input):

        # init globals
        global project_path, current_host, stored_hosts

        # run a default nmap scan if given no parameters and a current host is set
        if not input:

            # make sure a current host is set
            if not current_host:
                print("\nNo current host set! Set a host with \'switch <ip addr>\'\n")

            else:
                host = commands.default_scan(current_host, project_path + "/" + current_host + "/nmap")

                # check if we've already scanned this host
                if stored_hosts[current_host]:
                    new_info(stored_hosts[current_host], host)
                else:
                    stored_hosts[current_host] = host

        else:

            inps = input.split(" ")

            hosts_to_scan = []

            for inp in inps:

                if "." in inp:
                    hosts_to_scan.append(inp)

            if len(hosts_to_scan) == 0:
                hosts_to_scan.append(current_host)

            if inps[len(inps) - 1] == "all":
                for host in hosts_to_scan:
                    host_info = commands.all_scan(host, project_path + "/" + host + "/nmap-all")

                    if stored_hosts[host]:
                        new_info(stored_hosts[host], host_info)
                    else:
                        stored_hosts[host] = host_info

                    #


    def help_scan(self):

        print('\nUsage: \'scan [additional hosts] [scan-type]\'')
        print('\n- With no options, runs a default nmap scan against the current host (Ping scan + top 1000 tcp ports)\n')
        print('\nScan types other than default include:')
        print('\n- all: scans all tcp ports, performs service detection, os detection, and traceroute')
        print('\n- udp: scans the top 20 udp ports')


    def do_info(self, inp):

        # Given no input, print out the host info of current host
        if (not inp) and current_host:
            host_info(current_host)




if __name__ == '__main__':
    BaelishPrompt().cmdloop()
