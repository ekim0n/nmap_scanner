import nmap
import ipaddress
import re

from termcolor import colored



ascii_topic = [
    colored(r"      _    _                                                              ", 'red'),
    colored(r"     | |  (_)                                                             ", 'red'),
    colored(r"  ___| | ___ _ __ ___   ___  _ __                                         ", 'yellow'),
    colored(r" / _ \ |/ / | '_ ` _ \ / _ \| '_ \                                        ", 'green'),
    colored(r"|  __/   <| | | | | | | (_) | | | |                                       ", 'blue'),
    colored(r" \___|_|\_\_|_| |_| |_|\___/|_| |_|                                       ", 'red'),
    colored(r"                                                                           ", 'yellow'),
    colored(r"                                                                           ", 'green'),
    colored(r"                                                                           ", 'blue'),
    colored(r"                                                                           ", 'red'),
    colored(r"           _ __  _ __ ___   __ _ _ __                                     ", 'yellow'),
    colored(r"          | '_ \| '_ ` _ \ / _` | '_ \                                    ", 'green'),
    colored(r"          | | | | | | | | | (_| | |_) |                                   ", 'blue'),
    colored(r"          |_| |_|_| |_| |_|\__,_| .__/                                    ", 'red'),
    colored(r"                                | |                                       ", 'yellow'),
    colored(r"                                |_|                                       ", 'green'),
    colored(r"               ______          _   _____                                  ", 'blue'),
    colored(r"               | ___ \        | | /  ___|                                 ", 'red'),
    colored(r"               | |_/ /__  _ __| |_ \ `--.  ___ __ _ _ __  _ __   ___ _ __ ", 'yellow'),
    colored(r"               |  __/ _ \| '__| __| `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|", 'green'),
    colored(r"               | | | (_) | |  | |_/\__/ / (_| (_| | | | | | | |  __/ |   ", 'blue'),
    colored(r"               \_|  \___/|_|   \__\____/ \___\__,_|_| |_|_| |_|\___|_|   ", 'blue')
]

#You specify <lowest_port_number>-<highest_port_number> (example 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
#Initialising the prot numbers
port_min = 0
port_max = 65535

#This scanner uses Python nmap module to scan ports.
#You'll need to install following to get it work on Linux:
#If you have pip already installed:
#python -m pip install --upgrade pip
#If you dont have pip installed:
#sudo apt install python3-pip
#pip install python-nmap


#User interface
#Print ACSII art:
for line in ascii_topic:
    print(line)
print("\n****************************************************************")
print("\n*              Copyright of Aki Strömberg, 2024                *")
print("\n*                  https://github.com/ekim0n                   *")
print("\n****************************************************************")

# Ask user to input the ip address they want to scan
while True:
        ip_address_entered = input("\nPlease enter the ip address that you want to scan: ")
        #If entered ip is invalid, the block will go to except block and say "you entered wrong ip address"
        try:
            ip_address_object = ipaddress.ip_address(ip_address_entered)
            #This line will execute only, if the ip address is valid.
            print("You entered valid ip address.")
            break
        except:
             print("Ip address is no valid")

while True:
             #You can scan 0-65535 ports. This scanner is very basic and does not use multithreading so scannin all the port is not advised.
             print("Please enter the range of ports you want to scan in format: <int>-<int> (example would be 60-120)")
             port_range = input("Enter port range: ")
             #Program removes extra spaces around the numbers, so if you enter 80 - 90 instead of 80-90 the program will still work.
             port_range_valid = port_range_pattern.search(port_range.replace(" ",""))

             if port_range_valid:
                  #This extracts low end of the port scanner range the user wants to scan.
                  port_min = int(port_range_valid.group(1))
                  #This extracts upper end of the port scanner range the user wants to scan.
                  port_max = int(port_range_valid.group(2))
                  break

            
nm = nmap.PortScanner()
        # This loops all of the ports in specific range
for port in range(port_min, port_max + 1):
        try:
                  #add scan result to variable
            result = nm.scan(ip_address_entered, str(port))
                  #print(result)
                  #extracting the port status from returned object
            port_status = (result['scan'][ip_address_entered]['tcp'][port]['state'])
            print(f"Port {port} is {port_status}")
        except:
            #If program cannot scan the port, print an error
            print(f"Cannot scan port {port}")