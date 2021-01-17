# netscan.py

""" This tool was created for research purposes only. It can be used to gather information about software used on protocols specified by the
user. This tool will not exploit anything, however, it will momentarily establish a connection to a listening port and listen for a response
with the banner of the service. This program will continue to run until the user manually terminates all running instances. Use at your own risk! """


# import libraries
import socket
from ipaddress import IPv4Address
from random import randint
import re


def random_ip():
    """ Create a random IPv4 address, edit this function for particular country IP ranges """

    octets = []  # Add fixed IP octets (strings) for IP ranges, if changed, edit the range below.
    run = True
    
    while run:
        for x in range(4):  # Edit the range for the number of octets (max 4)
            octets.append(str(randint(0, 255)))
        ip = ".".join(octets)        
        
        if IPv4Address(str(ip)).is_global:
            return ip
        else:
            octets.clear()


def get_ip_range(ip):
    """ Take an IP address and iterate through host 1-255 and return a new list of ips """

    ips = []
    ip = ip.split(".")

    for x in range(1, 255 + 1):
        octets = [ip[0], ip[1], ip[2], str(x)]
        new_ip = ".".join(octets)

        if IPv4Address(str(new_ip)).is_global:
            ips.append(new_ip)
        else:
            pass

    return ips


def scanner(ip, port, timeout, bytes):
    """ Connect to a given host and port, grab and return banner """

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connection = s.connect_ex((ip, port))

        if connection == 0:
            banner = s.recv(bytes)
            s.close()
            print(banner)
            return banner

    except socket.timeout:
        pass
    except socket.error:
        pass


def http_scanner(ip, port, timeout, bytes):
    """ Connect to a given host and port, grab and return banner, change the scan port and use this
    function for http servers """

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connection = s.connect_ex((ip, port))

        if connection == 0:
            s.send(b"GET HTTP / 1.1")
            banner = s.recv(bytes)
            s.close()
            return banner

    except socket.timeout:
        pass
    except socket.error:
        pass


def ssh_banner_trim(ssh_raw_banner):
    """ Trim the ssh banner to retrieve service software and version """
    
    version = re.match(r"b'(.*?)\\r\\n'", str(ssh_raw_banner))

    if version:
        version = re.split(r"b'", str(version))
        version = re.split(r"\\(.*?)n", str(version[1]))
        version = version[0]
        print(version)
        return version


def write_to_file(data, file, mode="a+"):
    """ Write data to a file. Default write mode=append """

    with open(file, mode) as new_file:
        new_file.write(str(data))


def main():
    run = True

    while run:
        ip = random_ip()
        ip_list = get_ip_range(ip)

        for i in ip_list:
            raw_banner = scanner(i, 22, 0.2, 1024) # Edit these parameters to change the type of service to scan

            if raw_banner:
                banner = ssh_banner_trim(str(raw_banner))
                text = banner + " " + i + "\r\n"
                print(text)
                write_to_file(str(text), "ssh.txt")                


if __name__ == '__main__':
    main()
