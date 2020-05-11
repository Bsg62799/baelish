#!/usr/bin/env python3


# imports
from pyfiglet import Figlet
import clint
from PyInquirer import Validator, ValidationError
from PyInquirer import prompt, style_from_dict, Token
import os
import subprocess

# Project class, which holds all necessary fields for the current project
class Project:
    def __init__(self, target, directory, description):
        self.target = target
        self.dir = directory
        self.desc = description
        self.ports = []
        self.loot = []

# Dictionary of available functions
""" commands = {
    'scan': scan,


} """



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
    def validate(self, document):

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

            if os.path.isdir(effective_path + "/exploit") and os.path.isdir(effective_path + "/loot") and os.path.isdir(effective_path + "/notes") and os.path.isdir(effective_path + "/enumeration"):
                global project
                project = effective_path

            else:
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
        'name': 'newDir',
        'message': 'Relative path for new project?',
        'validate': NewDirValidator,
        'when': lambda info: info['new'] == True
    },

    {
        'type': 'input',
        'name': 'oldDir',
        'message': 'Relative path for exisiting project?',
        'validate': OldDirValidator,
        'when': lambda info: info['new'] == False

    },

    {
        'type': 'input',
        'name': 'target',
        'message': 'Target IP address?',
        'validate': HostValidator
    },

    {
        'type': 'input',
        'name': 'desc',
        'message': 'Description of this project?'
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
    info = prompt(questions, question_styles)

    # Create

if __name__ == '__main__':
    main()
