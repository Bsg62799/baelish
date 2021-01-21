#!/usr/bin/env python3

from cmd import Cmd
from stringcolor import *
import pyfiglet
import importlib
from os import path
import os
from libnmap.parser import NmapParser
import libnmap
import commands

# globals
stored_hosts = dict()
current_host = ""
project_path = ""
project_name = ""

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

        # print for spacing
        print('')

        # verify that the path exists, or make a new directory
        if not path.isdir(response):
            os.mkdir(response)

        # If the path does exist, load in existing data
        else:

            # Iterate through every dir (host) in the project folder
            for dir in os.listdir(response):

                # If available, load host from a all scan
                if 'nmap-all.xml' in os.listdir(response + '/' + dir):
                    info = NmapParser.parse_fromfile(response + '/' + dir + '/' + 'nmap-all.xml')
                    stored_hosts[dir] = info.hosts[0]

                # Otherwise, load host from a default scan
                elif 'nmap.xml' in os.listdir(response + '/' + dir):
                    info = NmapParser.parse_fromfile(response + '/' + dir + '/' + 'nmap.xml')
                    stored_hosts[dir] = info.hosts[0]

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
        if len(stored_hosts.keys()) == 1:
            current_host = list(stored_hosts.keys())[0]
            self.prompt = cs(project_name + '/' + current_host + "> ", "cyan")
        else:
            self.prompt = cs(project_name + ">", "cyan")


### Commands offered in our cmd loop

    def do_exit(self, inp):
        return True

    def help_exit(self):
        print('\nUsage: \'exit\'\n- Exits baelish and saves project files to a directory\n')

    def do_host(self, inp):

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
            else:
                print("\nHost " + host + " already stored as a host!\n" )

        for host in hosts:
            if host not in up_hosts:
                print("\nHost " + host + " is down!\n")

    # performs some type of nmap scan against a host or hosts
    def do_scan(self, input):

        # init globals
        global project_path
        global current_host
        global stored_hosts

        # run a default nmap scan if given no parameters and a current host is set
        if not input:

            # make sure a current host is set
            if not current_host:
                print("\nNo current host set! Set a host with \'switch <ip addr>\'\n")
            else:
                host = commands.default_scan(current_host, project_path + "/" + current_host + "/nmap")

                # check to see if the existing host already has a scan associated with it
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
                    commands.all_scan(host, project_path + "/" + host + "/nmap-all")


    def help_scan(self):

        print('\nUsage: \'scan [additional hosts] [scan-type]\'')
        print('\n- With no options, runs a default nmap scan against the current host (Ping scan + top 1000 tcp ports)\n')
        print('\nScan types other than default include:')
        print('\n- all: scans all tcp ports, performs service detection, os detection, and traceroute')
        print('\n- udp: scans the top 20 udp ports')


    def help_host(self):
        print('\nUsage: \'host <ip address> [additional ip addresses]\'' \
        '\n- Runs a ping scan against the provided host(s)' \
        '\n- Prints out whether host(s) is up and stores host that are up locally\n')

    def do_load(self, path):

        scan = NmapParser.parse_fromfile(path)

        print(scan.hosts[0].os_fingerprint)

    def do_show(self, inp):

        # init globals
        global current_host, stored_hosts

        # Test to just print out current ports
        if current_host:
            print(stored_hosts[current_host].get_ports())








if __name__ == '__main__':
    BaelishPrompt().cmdloop()
