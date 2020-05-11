#!/usr/bin/env python3


# imports
from pyfiglet import Figlet
import clint
import PyInquirer
import os
import subprocess

# global vars
project = ""

# Run a scan of all ports for target host
def enumerate(host):

    # Verify that the host is reachable

    # output = subprocess.check_output("ping -c 1 " + host, shell=True)

    # if not b'64 bytes from' in output:

        # raise Exception("Given host is not reachable")

    # Scan for ports, services and OS
    print("Scanning...")
    print(project)
    os.system('nmap -A -p- -o ' + project + '/enumeration/nmap.txt ' + host + ' > /dev/null')


# Generate a report based on notes stored in project directory
# def report():



def initialize(effective_path):

    # Create several sub directories for the project
    os.mkdir(effective_path + "/exploit")
    os.mkdir(effective_path + "/loot")
    os.mkdir(effective_path + "/notes")
    os.mkdir(effective_path + "/enumeration")



# Check to see if the given relative path exists
#   - if so, set that folder as the working directory
#   - if not, create a directory at the given relative path
def project_directory(path):

    # Combined cwd and given path
    effective_path = os.getcwd() + "/" + path

    print("Effective path: " + effective_path)

    # Verify if the project exists
    if os.path.isdir(effective_path):

        print("found")

    else:
        try:

            # Otherwise create a new project directory
            os.mkdir(effective_path)
            initialize(effective_path)

        except:
            raise Exception("Error: Could not write to path")


    global project
    project = effective_path

def main():

    # Print Title
    format = Figlet(font='slant')
    print(clint.textui.colored.red(format.renderText('Cyber Scribe')))

    # Print Greeting
    print('Welcome to Cyber Scribe')

    project_directory("Tester")
    enumerate("10.10.10.171")

if __name__ == '__main__':
    main()
