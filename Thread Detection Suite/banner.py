# banner.py
import pyfiglet
from termcolor import colored

def print_banner():
    ascii_art = pyfiglet.figlet_format("Threat Detection Suite")
    print(colored(ascii_art, "cyan"))
    print(colored("********************************************************", "cyan"))
    print(colored("------------------- By Aman Singh ----------------------", "cyan"))
    print(colored("********************************************************\n", "cyan"))
