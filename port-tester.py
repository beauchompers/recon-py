#! /usr/bin/env python3
# simple script to test if a port is open on a host. 

import argparse
import sys
import socket
import ipaddress

# validate params
def validate_params(ip, port):
    #validate if the ip is actually an ip before we search
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Error: {} is not a valid ip address...".format(ip))
        sys.exit(1)

    try: 
        port = int(port)
        type(port) == int
    except:
        print("Error: {} is not a valid port...".format(port))
        sys.exit(1)

    return True

# test the ip and port
def port_test (ip, port, report=False):
    print("\nTesting: {} on Port: {}".format(ip, port))
    try:
        host = ip
        port = int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host,port))
        if result == 0:
            if report:
                filename = ip + "-" + str(port) + ".txt"
                text_file = open(filename, "a")
                text_file.write("{},{}".format(ip,port))
                text_file.close()
            print("Port is open.\n")
        else:
            print("Port is not open.\n")
            
    except Exception as e:
        print (e)
        print ("No results on IP: {}".format(ip))

def __main__():
    # port tester script

    # grab args,
    print("Port Tester, tests if a port is open on an IP")
    parser = argparse.ArgumentParser(description='Port Tester Script')
    parser.add_argument('--ip', '-i', dest='ip', help='ip address to test')
    parser.add_argument('--port', '-p', dest='port', help='port to test')
    parser.add_argument('--file', dest='file', action='store_true', default=False, help='output results to a text file')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    test = validate_params(args.ip, args.port)

    if test:
        port_test(args.ip, args.port, args.file)

    print("Port test completed")
    sys.exit()

if __name__ == '__main__':
    __main__()
