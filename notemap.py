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
import json


# text constants
DIVIDER = "-------------------------------------"


"""globals"""

# a dictionary of host objects that contains port and os information
stored_hosts = dict()

# The host that commands will use if none is specified
current_host = ""

# path to the project dir
project_path = ""

# Name of the project
project_name = ""

# Notes are stored in the form: {host.ipv4, (port #, 'OS', or host.ipv4, note_content)}
stored_notes = dict()

"""Supporting helper methods"""

"""
Prints the provided string to stdout in cyan
"""
def cyan(text):

    print(cs(text, "cyan"))

"""
Levies the lipnmap method diff() to compare an existing host object against a new host
object derived from an nmap scan. This is critical to ensure that, for example, a host that
was derived from an intense nmap scan the performed service detection against every port is
not replaced by a host object that simply contains the open ports (default scan result).
"""
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

"""
Given a host's ip address, host_info checks for the existence of said host and if found,
prints out all information of the stored host object.
"""
def host_info(host_ip):

    # Ensure the host exists
    if not host_ip in stored_hosts.keys():
        print("Host does not exist!")
        return

    # host object
    host = stored_hosts[host_ip]

    # header
    print("\nHost details for " + host_ip + "\n" + DIVIDER)

    # print general notes on the host if any`
    if host_ip in stored_notes[host_ip].keys():
        print("\nGeneral Host Notes:\n" + DIVIDER)

        for note in stored_notes[host_ip][host_ip]:
            print(" * " + note)

    # print scanned ports and services if available
    print("\nOpen TCP Ports:\n" + DIVIDER)

    for port in host.get_open_ports():

        # Ensure port is tcp
        if port[1] == 'tcp':
            service = host.get_service(port[0], port[1])
            print(" * Port " + str(port[0]) + " - " + service.service + " - " + service.banner.split("product:")[1].split("extrainfo:")[0])

        # iterate through any notes associated with the port
        if str(port[0]) in stored_notes[host_ip].keys():
            for note in stored_notes[host_ip][str(port[0])]:
                print("  -> " + note)

    # print os information if available
    if host.os_fingerprinted:
        if "SCAN" in host.os_fingerprint:
            print("\nOS: No Match")

        else:
            print("\n" + host.os_fingerprint)


    # If no OS detection was performed, print N/A
    else:
        print("\nOS: N/A")

    # print the os divider
    print(DIVIDER)

    # regardless of if there is any os information from nmap, print any notes associated with it
    if 'os' in stored_notes[host_ip].keys():
        for note in stored_notes[host_ip]['os']:
            print("  -> " + note)

    # if there's any loot, print it out
    if 'loot' in stored_notes[host_ip].keys():

        print("\nLoot:\n" + DIVIDER)
        for note in stored_notes[host_ip]['loot']:
            print("  -> " + note)

    # formating newline
    print()

"""
Interactive shell built on cmd library
"""
class NotemapPrompt(Cmd):

    # Set the ruler used for the help command
    Cmd.ruler = '-'


    def help_note(self):
        cyan('\nUsage: \'note [HOST OPTIONS] [NOTE OPTIONS] [NOTE TYPES] <note-content>\'\n' \
        '\n- Leaves a note in the form of a text string <note-content> against an attribute of a host' \
        '\n- Given no options, a general note is attached to the current host if set\n' \
        '\nHOST OPTIONS:' \
        '\n -h <host> : Saves the content of the note to the specified host\n' \
        '\nNOTE OPTIONS'
        '\n -c <type> : Clears the content of the specified type (ex. note -c -p 80 clears notes for port 90 on current host)\n'
        '\nNOTE TYPES'
        '\n -p <port> : Saves the content of the note to the port (port#) attribute if it exists for the set host' \
        '\n -o        : Saves the content of the note to the OS attribute of the host' \
        '\n -l        : Saves the content of the note as loot associated with the host\n')


    """
    Prints usage for the host command
    """
    def help_host(self):

        cyan('\nUsage: \'host <ip address> [additional ip addresses]\'' \
        '\n- Runs a ping scan against the provided host(s)' \
        '\n- Prints out whether all host(s) that responded to the ping scan and adds them to the project\n')

    """
    Prints usage for the help command
    """
    def help_scan(self):

        cyan('\nUsage: \'scan [additional hosts] [scan-type]\'\n' \
        '\n- Given no arguments, runs a default nmap scan against the current host (Ping scan + top 1000 tcp ports)\n' \
        '\nScan types other than default include:' \
        '\n- all: scans all tcp ports, performs service detection, os detection, and traceroute' \
        '\n- udp: scans the top 20 udp ports')

    """
    Prints usage for the info command
    """
    def help_info(self):

        cyan('Usage: \'info [host ip addr]\'\n' \
        '\n- Given no arguments, prints out all info on the current host if set' \
        '\n- Otherise, prints out all info on the provided host')

    """
    Prints usage for the exit command
    """
    def help_exit(self):
        cyan('\nUsage: \'exit\'\n- Exits baelish and saves any project notes\n')

    """
    Requests a directory path from the user, either to create a new project at said path
    or provide the path of an exisiting notemap project.
    Iterates through nmap-scans and json note files in the given path if the user provides
    the path of an existing notemap project.
    """
    def preloop(self):

        # Set the path for the project
        global project_path, current_host, stored_hosts, project_name
        response = input(cs(pyfiglet.figlet_format("NoteMap", font="slant"), "cyan") + \
        "Welcome to notemap, a tool to aid in handling information for penetration tests" \
        "\nTo get started, enter a new or exisiting project path: ")

        # store the project path for file output later
        project_path = response

        # Derive the name for the project from the path
        if '/' in project_path:
            dirs = project_path.split('/')
            project_name = dirs[len(dirs) - 1]
        else:
            project_name = project_path


        # verify that the path exists, or make a new directory
        if not path.isdir(response):
            os.mkdir(response)
            cyan("\nCreated new project: " + project_name + \
            "\nUse the host <ip addr> command to add a target to scan\n")

        # If the path does exist, load in existing data
        else:

            # Iterate through every dir (host) in the project folder
            for dir in os.listdir(response):
                dir_contents = os.listdir(response + '/' + dir)

                # Check to see if notes exist for this host
                if 'notes.json' in dir_contents:
                    json_path = response + '/' + dir + '/' + 'notes.json'
                    with open(json_path) as json_file:
                        stored_notes[dir] = json.load(json_file)

                # Otherwise just init a notes dict
                else:
                    stored_notes[dir] = dict()

                # If available, load host from an all scan
                if 'nmap-all.xml' in dir_contents:
                    info = NmapParser.parse_fromfile(response + '/' + dir + '/' + 'nmap-all.xml')
                    stored_hosts[dir] = info.hosts[0]

                # Otherwise, load host from a default scan
                elif 'nmap.xml' in dir_contents:
                    info = NmapParser.parse_fromfile(response + '/' + dir + '/' + 'nmap.xml')
                    stored_hosts[dir] = info.hosts[0]

                # Otherwise initailize an empty dict entry
                else:
                    stored_hosts[dir] = dict()


                # Print out hosts that were loaded in:
                print(cs("\nLoaded existing project: ", "cyan") + project_name + \
                cs("\nHost(s) loaded: ", "cyan"), end='')

                # print hosts
                for host in stored_hosts.keys():
                    print(host + " ", end='')

        # set current_host and notify user if only one host in project
        if len(os.listdir(response)) == 1:
            current_host = os.listdir(response)[0]
            self.prompt = cs(project_name + '/' + current_host + "> ", "cyan")
            print(cs("\nOnly one host in project, setting current host to: ", "cyan") + current_host + "\n")

        else:
            self.prompt = cs(project_name + ">", "cyan")

    """
    Allows a user to execute bash commands
    """
    def do_shell(self, inp):

        os.system(inp)

    """
    Saves any notes to a json file and exits the cmdloop.
    """
    def do_exit(self, inp):

        # Write the note dict to an output file note.json
        for host in stored_hosts.keys():
            with open(project_path + '/' + host + '/notes.json', "w") as note_file:
                json.dump(stored_notes[host], note_file)

        # break the loop
        return True

    """
    Allows a user to add a host or set of hosts to a project
    This runs a ping scan against the host to ensure it is up before adding
    it to stored_hosts
    """
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
                stored_notes[host] = {}

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

    """
    Given no arguments, runs a default nmap scan as defined in commands.py against the current host if set.
    Otherwise, runs nmap scans against the specified host or hosts. Scans can be specified as 'all' or 'udp'
    at the end of the command args. Otherwise, a default scan is run
    TODO: Implement UDP, postponing because it really doesn't come up for HTB
    """
    def do_scan(self, input):

        # init globals
        global project_path, current_host, stored_hosts

        # run a default nmap scan if given no parameters and a current host is set
        if not input:

            # make sure a current host is set
            if not current_host:
                print("\nNo current host set! Set a host with \'switch <ip addr>\'\n")

            else:

                # Run a default nmap scan and receive a libnmap host object
                host = commands.default_scan(current_host, project_path + "/" + current_host + "/nmap")

                # check if we've already scanned this host
                if stored_hosts[current_host]:

                    # if we have, make sure we're not overwriting data
                    new_info(stored_hosts[current_host], host)

                else:
                    stored_hosts[current_host] = host


        # parse args if given
        else:

            # break up the given command arguments
            args = input.split(" ")

            # init list of hosts to scan
            hosts_to_scan = []

            # process arguments
            for arg in args:
                if "." in arg:
                    hosts_to_scan.append(inp)


            if len(hosts_to_scan) == 0:
                hosts_to_scan.append(current_host)

            # If the given scan type is all, run intense nmap scans against given hosts
            if args[len(args) - 1] == "all":

                # run all scan against all hosts
                for host in hosts_to_scan:

                    # we don't need to check these hosts against existing host objects, since
                    # default scans will always provide more info than default ones
                    host_info = commands.all_scan(host, project_path + "/" + host + "/nmap-all")
                    stored_hosts[host] = host_info



    # Allows the user to leaves notes on scanned ports,
    # operating systems, or hosts in general
    def do_note(self, inp):

        # init globals
        global stored_notes

        # some vars for simplicity
        host = current_host
        max_index = 0
        clear = False
        args = inp.split(' ')

        # set the host of this note if given -h
        if '-h' in args:

            # get index of host command and given host
            index = args.index('-h') + 1
            host = args[index]

            # ensure the host exists
            if not host in stored_hosts.keys():
                print(host + " is not a stored host! Add a host with host <ip addr>")
                return

            # keep track of max index for the sake of getting note content
            if index > max_index:
                max_index = index


        # check if we're clearing notes
        clear = '-c' in args

        # if the only given command is -c, clear general notes
        if clear and len(args) == 1:
            if host in stored_notes[host].keys():
                del stored_notes[host][host]
                return

        # given no options, leave a general note on the current host
        if not ('-' in inp):
            if not host in stored_notes[host].keys():
                stored_notes[host][host] = [inp]
            else:
                stored_notes[host][host].append(inp)
            return


        # if given -p associate the note with the provided port # of the host
        if '-p' in args and not '-o' in args and not '-l' in args:

            # get the index of the port value
            index = args.index('-p') + 1
            port = args[index]

            # ensure the port exists for the set host
            port_list = [port_tuple[0] for port_tuple in stored_hosts[host].get_open_ports()]
            if not (int(port) in port_list):
                print(port + " is not an open port for host " + host + "!")
                return

            # if we're clearing, make sure the notes exist and then delete them
            if clear:
                if str(port) in stored_notes[current_host].keys():
                    del stored_notes[host][str(port)]
                    return

            # keep track of max index for the sake of getting note content
            if index > max_index:
                max_index = index

            # if no notes exist for the specified port, init a list of notes. Otherwise append
            if not str(port) in stored_notes[host].keys():
                print((" ".join(args[max_index + 1:])))
                stored_notes[host][str(port)] = [(" ".join(args[max_index + 1:]))]
            else:
                stored_notes[host][str(port)].append(" ".join(args[max_index + 1:]))

        # if given -o associate the note with the os of the host
        elif '-o' in args and not '-p' in args and not '-l' in args:

            # get the index of the -o arg
            index = args.index('-o')

            # if we're clearing, make sure the notes exist and then delete them
            if clear:
                if 'os' in stored_notes[current_host].keys():
                    del stored_notes[host]['os']
                    return

            # keep track of the max index for the sake of getting note content
            if index > max_index:
                max_index = index

            # if no notes exist for the host's os, init a list of notes. Otherwise append
            if not 'os' in stored_notes[host].keys():
                stored_notes[host]['os'] = [(" ".join(args[max_index + 1:]))]
            else:
                stored_notes[host]['os'].append(" ".join(args[max_index + 1:]))

        # if given -l mark the note as loot associated with the host
        elif '-l' in args and not '-p' in args and not '-o' in args:

            # get the index of the -l arg
            index = args.index('-l')

            # if we're clearing, make sure the notes exist and then delete them
            if clear:
                if 'loot' in stored_notes[current_host].keys():
                    del stored_notes[host]['loot']
                    return

            # keep track of max index for the sake of getting note content
            if index > max_index:
                max_index = index

            # if no notes exist for the host's os, init a list of notes. Otherwise append
            if not 'loot' in stored_notes[host].keys():
                stored_notes[host]['loot'] = [(" ".join(args[max_index + 1:]))]
            else:
                stored_notes[host]['loot'].append(" ".join(args[max_index + 1:]))

        # otherwise print usage
        else:
            self.help_note()
            return

    """
    Calls the helper method host_info against the current host if no args are provided
    or against the provided host. TODO: Allow user to specify viewing specific types of information on the host
    """
    def do_info(self, args):

        # Given no input, print out the host info of current host
        if (not args) and current_host:
            host_info(current_host)

        # Otherwise ensure we get a single host as an arg
        elif len(args.split(" ")) == 1:
            if args in stored_hosts.keys():
                host_info(args)
            else:
                self.help_info()

        # Otherwise print usage
        else:
            self.help_info()




if __name__ == '__main__':

    NotemapPrompt().cmdloop()
