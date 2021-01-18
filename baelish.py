#!/usr/bin/env python3

from cmd import Cmd
from stringcolor import *
import pyfiglet
import importlib
from os import path
import os

import commands

# globals
stored_hosts = dict()
current_host = ""
project_path = ""
project_name = ""

# Interactive Shell
class BaelishPrompt(Cmd):

    # Prompt and welcome statement
    intro = cs("\n----------------------------------\n" + pyfiglet.figlet_format("Baelish", font="slant")\
     + ""  \
    "----------------------------------\n\n" \
    "Welcome to baelish, a tool to aid in handling information for penetration tests" \
        "\nTo get started, add a target to the project with the command \'host <ip addr>\'" \
        "\nType ? to list available commands\n", "cyan")

    # Establish a project directory before entering command loop
    def preloop(self):

        # Set the path for the project
        global project_path
        response = input('Enter a new or exisiting project path: ')

        # verify that the path exists, or make a new directory
        if not path.isdir(response):
            os.mkdir(response)

        project_path = response

        # Derive the name for the project from the path
        global project_name
        if '/' in project_path:
            dirs = project_path.split('/')
            project_name = dirs[len(dirs) - 1]
        else:
            project_name = project_path

        # update the visual prompt to show project name
        self.prompt = cs(project_name + "> ", "cyan")

    def do_exit(self, inp):
        return True

    def help_exit(self):
        print('\nUsage: \'exit\'\n- Exits baelish and saves project files to a directory\n')

    def do_host(self, inp):

        # split up provided hostnames or addresses
        hosts = inp.split(' ')

        # run a ping scan against the targets and receive a report
        report = commands.ping_scan(hosts)
        host_array = report.hosts

        # display hosts that responded to the scan and add them to global hosts
        for host in host_array:

            global stored_hosts

            if host.is_up() and host.ipv4 not in stored_hosts.keys():

                # If the host is up, notify the user and store it
                print("\nHost " + host.ipv4 + " is up, stored as an host!\n")
                stored_hosts[host.ipv4] = host

                # if the host is up and unique, create a directory for it
                global project_path
                os.mkdir(project_path + "/" + host.ipv4)

                # if only one host was given, set current_host
                if len(host_array) == 1:
                    global current_host
                    current_host = host.ipv4
                    self.prompt = cs(project_name + "/" + current_host + "> ", "cyan")

            else:

                if not host.ipv4 in stored_hosts.keys():
                    print("Host " + host.ipv4 + " is down!")
                else:
                    print("Host " + host.ipv4 + " already stored as a host!" )

    def do_scan(self, input):

        global project_path
        global current_host

        # run a default nmap scan if given no parameters and a current host is set
        if not input:

            # make sure a current host is set
            if not current_host:
                print("\nNo current host set! Set a host with \'switch <ip addr>\'\n")
            else:
                commands.default_scan(current_host, project_path + "/" + current_host + "/nmap-all.txt")



    def help_scan(self):

        print('\nUsage: \'scan [additional hosts] [scan-type]\'')
        print('\n- With no options, runs a default nmap scan against the current host (Ping scan + top 1000 tcp ports)\n')
        print('\nScan types other than default include:')
        print('\n  - all: scans all tcp ports, performs service detection, os detection, and traceroute')
        print('\n  - udp: scans the top 20 udp ports')


    def help_host(self):
        print('\nUsage: \'host <ip address> [additional ip addresses]\'' \
        '\n- Runs a ping scan against the provided host(s)' \
        '\n- Prints out whether host(s) is up and stores host that are up locally\n')





if __name__ == '__main__':
    BaelishPrompt().cmdloop()
