#!/usr/bin/env python3

from cmd import Cmd
from stringcolor import *
import pyfiglet

# globals
hosts = dict()

# Interactive Shell
class BaelishPrompt(Cmd):

    # Prompt and welcome statement
    prompt = cs('> ', "cyan")
    intro = cs(pyfiglet.figlet_format("Baelish", font="slant") + ""  \
    "----------------------------------\n\n" \
    "Welcome to baelish, a tool to aid in handling information for penetration tests" \
        "\nTo get started, add a target to the project with the command \'host <ip addr>\'" \
        "\nType ? to list available commands\n", "cyan")


    def do_exit(self, inp):
        return True

    def help_exit(self):
        print('\nUsage: \'exit\'\n- Exits baelish and saves project files to a directory\n')

    def do_host(self, inp):
        print(inp)

    def help_host(self):
        print('')






if __name__ == '__main__':
    BaelishPrompt().cmdloop()
