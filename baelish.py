#!/usr/bin/env python3


# imports
from pyfiglet import Figlet
import clint
from PyInquirer import Validator, ValidationError
from PyInquirer import prompt, style_from_dict, Token
import os
import subprocess
import json
import nmap3

# Project class, which holds all necessary fields for the current project
class Project:
    def __init__(self, target, directory, description):
        self.target = target
        self.dir = directory
        self.desc = description
        self.ports = []
        self.loot = []

global current_project


# Informal interface for commands
class CommandInterface:

    """Return information regarding the command"""
    def help(self) -> str:
        pass

    """Execute some sort of functionality based on the current global project"""
    def execute(self, args):
        pass

class Enumerate(CommandInterface):

    def help(self):
        return '\nscans the set target for open ports and services\nUsage: enumerate [lite full]\n  Lite: scans the top 20 most popular ports\n    Full: scans all tcp ports and performs OS detection'

    def execute(self, args):

        if not len(args) == 1:

            print(self.help())

        elif args[0] == "lite":

            os.system('nmap -F ' + current_project.target + ' -o ' + current_project.dir + '/enumeration/nmap_lite.txt')

        elif args[0] == "full":

            os.system('nmap -p- -O ' + current_project.target + ' -o ' + current_project.dir + '/enumeration/nmap_full.txt')

        else:

            print(self.help())


# Class to exit baelish
class Exit(CommandInterface):

    def help(self):
        return '\nexits baelish and writes the current project to a json'

    def execute(self, args):
        pass


# Class to print help messages for given commands
class Help(CommandInterface):

    def help(self):
        return '\nprints a list of all available commands\n can also be used alongside another command: (i.e.\'help command\')'

    def execute(self, args):

        # If given no args print all available commands
        if not args:

            # print help message
            print(self.help())

            print('\n   Available commands:\n   ----------------------')
            for command in commands.keys():
                print('  - ' + command)

            print('\n')

        # If given a command argument, print information about the command
        elif len(args) == 1:

            # Check that the command exists
            if args[0] in commands.keys():

                # Print command help info
                print(commands[args[0]].help())

            else:

                print('Given command not found!')

        # Error if given too many arguments
        else:

            print('Given too many arguments! Use help alongside a single other command')

# Command to input a bash command while still running baelish
class Bash(CommandInterface):

    def help(self):
        return "the command bash can be used to execute bash commands (i.e. \'bash clear\')"

    def execute(self, args):

        if not args:
            print('Bash does nothing without commands that follow!')

        else:

            bash_command = ""

            for arg in args:
                bash_command = bash_command + ' ' + arg + ' '

            os.system(bash_command)


# Dictionary of available commands
commands = {
    #'scan': scan,
    'help': Help(),
    'bash': Bash(),
    'enumerate': Enumerate(),
    'exit': Exit()
}


# Check that the given host is legitimate and reachable
class HostValidator(Validator):
    def validate(self, document):
        try:
            subprocess.check_output("ping -c 1 " + document.text, shell=True)
        except:
            raise ValidationError(
                message='Given target is invalid or unreachable. Try again:',
                cursor_position=len(document.text))


# Check that the given project directory does not exist and can be created
class NewDirValidator(Validator):
    def validate(self, document):# Dictionary of available commands

        # Set effective path
        effective_path = os.getcwd() + "/" + document.text

        if os.path.isdir(effective_path):
            raise ValidationError(
            message='Directory already exists at given path. Try again',
            cursor_position=len(document.text))


        else:

            try:
                os.mkdir(effective_path)
                os.mkdir(effective_path + "/exploit")
                os.mkdir(effective_path + "/loot")
                os.mkdir(effective_path + "/notes")
                os.mkdir(effective_path + "/enumeration")

                global project
                project = effective_path

            except:
                raise ValidationError(
                message='Could not create project directories at given path. Try again',
                cursor_position=len(document.text))

# Check that the given project directory exists and has the necessary subdirectories
class OldDirValidator(Validator):
    def validate(self, document):

        # Set effective path
        effective_path = os.getcwd() + "/" + document.text

        if not os.path.isdir(effective_path):
            raise ValidationError(
            message='Directory does not exist at given path. Try again',
            cursor_position=len(document.text))


        else:

            if not (os.path.isdir(effective_path + "/exploit") and os.path.isdir(effective_path + "/loot") and os.path.isdir(effective_path + "/notes") and os.path.isdir(effective_path + "/enumeration") and os.path.isfile(effective_path + "/info.txt")):
                raise ValidationError(
                message='Missing subdirectories at given path, not a baelish project. Try again',
                cursor_position=len(document.text))






# List of necessary setup questions
questions = [

    {
        'type': 'confirm',
        'name': 'new',
        'message': 'Create a new project?',
        'default': True
    },

    {
        'type': 'input',
        'name': 'Dir',
        'message': 'Relative path for new project?',
        'validate': NewDirValidator,
        'when': lambda info: info['new'] == True
    },

    {
        'type': 'input',
        'name': 'Dir',
        'message': 'Relative path for exisiting project?',
        'validate': OldDirValidator,
        'when': lambda info: info['new'] == False

    },

    {
        'type': 'input',
        'name': 'target',
        'message': 'Target IP address?',
        'validate': HostValidator,
        'when': lambda info: info['new'] == True
    },

    {
        'type': 'input',
        'name': 'desc',
        'message': 'Description of this project?',
        'when': lambda info: info['new'] == True
    }
]

# Run a scan of all ports for target host
def scan(host):

    # Verify that the host is reachable

    output = subprocess.check_output("ping -c 1 " + host, shell=True)

    if not b'64 bytes from' in output:

        raise Exception("Given host is not reachable")

    # Scan for ports, services and OS
    print("Scanning...")
    os.system('nmap -A -p- -o ' + project + '/enumeration/nmap.txt ' + host + ' > /dev/null')


def main():

    # Print Title
    format = Figlet(font='slant')
    print(clint.textui.colored.yellow('------------------------------------'))
    print(clint.textui.colored.yellow(format.renderText('Baelish')))
    print(clint.textui.colored.yellow('       \x1B[3m\"Knowledge is power\"\x1B[23m'))
    print(clint.textui.colored.yellow('------------------------------------\n'))

    # Get project information
    info = prompt(questions)

    # Write current fields to file if new project
    if info['new']:
        with open(info['Dir'] + "/info.txt", "w") as f:
            f.write(json.dumps(info))

    # Otherwise load fields from existing info.txt
    else:
        with open(info['Dir'] + "/info.txt") as file:
            fields = json.load(file)
            info['target'] = fields['target']
            info['desc'] = fields['desc']

    # Construct project object
    global current_project
    current_project = Project(info['target'], info['Dir'], info['desc'])

    while True:

        # Await instruction
        command = input(clint.textui.colored.yellow("> "))
        args = command.split()
        command = args.pop(0)

        # Check if command exists
        if command in commands.keys():
            commands[command].execute(args)

        # Check for exit
        if command == 'exit':
            break

    # Write current project to it's info file
    with open(info['Dir'] + "/info.txt", "w") as f:
        f.write(json.dumps(current_project.__dict__))

if __name__ == '__main__':
    main()
