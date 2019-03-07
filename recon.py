#!/usr/bin/env python3
# simple nmap script to recon a host or network.
# accepts an ip or cidr, and a range of ports.  
# script has been coded to only allow scanning private networks for which you have permission.

# modules
import nmap
import masscan
import sys
import argparse
import ipaddress
import os

# utility functions

# check nmap / masscan are installed on the host
def checktools():

    try:
        nmap.PortScanner()    
    except nmap.PortScannerError:
        print("Error: NMap not found...")
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

    try:
        masscan.PortScanner()         
    except masscan.PortScannerError:
        print("Error: Masscan not found...")
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)
    
    return True

# pretty print dictionaries.
def printdict(d, tabs=False):
  for k, v in d.items():
    if isinstance(v, dict):
        print("{}:".format(k))
        printdict(v, tabs=True)
    else:
        if tabs:
            print("\t{} : {}".format(k, v))
        else:
            print("{} : {}".format(k, v))

# validate ip address or cidr block
def validate_ip(ip):
    #validate if the ip or cidr is actually an ip before we search
    try:
        ipaddress.ip_network(ip)
    except ValueError:
        print("Error: {} is not a valid ip or cidr block...".format(ip))
        sys.exit(1)

    # with great power... only scan on private networks
    try:
        ipaddress.IPv4Network(ip).is_private 
    except ValueError:
        print("Error: {} is not a private network range or ip, script doesn't do that".format(ip))
        sys.exit(1)

    return True

def validate_ports(ports):
    # validate the ports
    r = range(0,65536)
    try: 
        port = ports.split('-')
        if len(port) <= 2:
            for x in port:
                num = int(x)
                if not num in r:
                    sys.exit(1)
        else: 
            sys.exit(1)
    except:
        print("Error: {} is not a valid port or port range...".format(ports))
        sys.exit(1)

    return True

# create folder for results if required
def createfolder():
    path = os.getcwd() + "/results/"
    try:  
        if not os.path.exists(path):
            os.mkdir(path)
    except OSError:  
        print("Creation of the directory {} failed".format(path))

    return path

# core functions
# masscan for ports
def runmasscan(ip, ports, rate):
    # run massscan
    args = "--max-rate {}".format(rate)
    
    print("Starting Masscan... grab a coffee...")
    try:
        mas = masscan.PortScanner()
        mas.scan(ip, ports=ports, arguments=args, sudo=True)
        result = mas.scan_result['scan']
    except Exception as e:
        print("Error during Masscan: {} ".format(e))
        sys.exit(1)

    print("Masscan Results:")
    for host in result:
        portlist = list(result[host]['tcp'].keys())
        portlist.sort()
        portlist = ','.join(map(str, portlist))
        print("Host: {}, Ports: {}".format(host, portlist))

    return result

def runnmap(ip, ports, report=False, verbose=False):
    # run nmap
    ports = ','.join([str(port) for port in ports])

    if report:
        folder = createfolder()
        args = "-A -oN " + folder + ip + ".nmap.txt"
    else: 
        args = "-A"

    print("\nStarting NMap Scan...this may take a while...")
    print("\nScanning {} on the following ports: {}\n".format(ip, ports))

    try:
        nm = nmap.PortScanner() # instantiate nmap.PortScanner object
        nm.scan(ip, ports=ports, arguments=args, sudo=True)
        print("NMap Command: {}\n".format(nm.command_line()))

        for host in nm.all_hosts():
            print("-" * 30)
            print("Host : {} ({})".format(host, nm[host].hostname()))
            print("State : {}".format(nm[host].state()))
            for proto in nm[host].all_protocols():
                print("-" * 20)
                print("Protocol : {}".format(proto))
                lport = sorted(nm[host][proto].keys())
                for port in lport:
                    if verbose:
                        print("-" * 20)
                        print("port : {}".format(port))
                        printdict(nm[host][proto][port])
                        print(" ")
                    else:
                        print("port: {}, state: {}, name: {}, product: {}, version: {}".format(port, nm[host][proto][port]['state'], nm[host][proto][port]['name'], nm[host][proto][port]['product'], nm[host][proto][port]['version']))

    except Exception as e:
        print("Error during NMap scan: {} ".format(e))
        sys.exit(1)

def __main__():
    # recon scan script

    # grab args,
    print("Recon Scan")
    parser = argparse.ArgumentParser(description='Recon Scan')
    parser.add_argument('--ip', '-i', dest='ip', help='ip address or cidr (i.e 192.168.8.0/24) to scan. Note: Will only scan private networks.')
    parser.add_argument('--ports', '-p', dest='ports', default='0-65535', help='port range to scan, example 0-443 or 22,135,443')
    parser.add_argument('--rate', '-r', dest='rate', default='500', choices=['500', '1000'], help='rate for masscan packets, default 500, max 1000')
    parser.add_argument('--file', dest='file', action='store_true', default=False, help='output nmap results to a text file')
    parser.add_argument('--verbose', dest='verbose', action='store_true', default=False, help='print more results to console')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    # validate we have the tools for the job
    checktools()

    # validate params before kicking things off
    validate_ip(args.ip)
    validate_ports(args.ports)

    # run masscan
    scan = runmasscan(args.ip, args.ports, args.rate)

    # run nmap against masscan results
    for host in scan:
        portlist = list(scan[host]['tcp'].keys())
        portlist.sort()
        runnmap(host, portlist, args.file, args.verbose)

    print("\nRecon completed...")
    sys.exit(0)

if __name__ == '__main__':
    __main__()