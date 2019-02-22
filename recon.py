#!/usr/bin/env python3
# simple nmap script to recon a host

import nmap
import masscan
import subprocess
import sys
import re
import argparse
import ipaddress

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

# validate params
def validate_params(ip, ports):
    #validate if the ip is actually an ip before we search
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Error: {} is not a valid ip address...".format(ip))
        sys.exit(1)

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

# core functions

# masscan for ports
def runmasscan(ip, ports, rate):
    # run massscan
    try:
        cmd = ["sudo", "masscan", "-p " + ports, "--max-rate", rate, ip]
        print("\nMasscan Command: "+' '.join(cmd))
        sp = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = ""
        while True:
            out = sp.stdout.read(1).decode('utf-8')
            if out == '' and sp.poll() != None:
                break
            if out != '':
                output += out
                sys.stdout.write(out)
                sys.stdout.flush()

        # getting discovered ports from the masscan output and sorting them
        results = re.findall("port (\d*)", output)
        if results:
            ports = list({int(port) for port in results})
            ports.sort()

    except Exception as e:
        print("Error during Masscan: {} ".format(e))
        sys.exit(1)

    return ports

def runnmap(ip, ports, report=False, verbose=False):
    # run nmap
    ports = ','.join([str(port) for port in ports])

    if report:
        args = "-A -oN " + ip + ".nmap.txt"
    else: 
        args = "-A"

    print("\nStarting NMap Scan...")
    print("\nScanning the following ports: {}\n".format(ports))

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
    print("Recon Scan, recons a host using masscan/nmap")
    parser = argparse.ArgumentParser(description='Recon Scan')
    parser.add_argument('--ip', '-i', dest='ip', help='ip address to scan')
    parser.add_argument('--ports', '-p', dest='ports', default='0-65535', help='port range to scan, example 0-443 or 22,135,443')
    parser.add_argument('--rate', '-r', dest='rate', default='500', choices=['500', '1000'], help='rate for masscan packets, default 500, max 1000')
    parser.add_argument('--file', dest='file', action='store_true', default=False, help='output nmap results to a text file')
    parser.add_argument('--verbose', dest='verbose', action='store_true', default=False, help='print more results to console')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    # validate we have the tools for the job
    checktools()

    # validate params before kicking things off
    valid = validate_params(args.ip, args.ports)

    if valid:
        openports = runmasscan(args.ip, args.ports, args.rate)
        runnmap(args.ip, openports, args.file, args.verbose)

    print("\nRecon completed...")
    sys.exit(0)

if __name__ == '__main__':
    __main__()