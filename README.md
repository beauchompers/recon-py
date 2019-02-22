# Python Recon Scripts

Work in progress, various Python scripts for recon or network testing.

## recon.py

Runs a masscan scan on a host to get open ports, and then runs nmap against those ports to grab services and versions.  Prints results to console, or optionally will output nmap results to a text file.

```console
$ ./recon.py --ip 192.168.8.8 --ports 0-1024
$ ./recon.py --ip 192.168.8.8 --ports 0-65535 --file # outputs to 192.168.1.10.nmap.txt

$ ./recon.py -h
Recon Scan, recons a host using masscan/nmap
usage: recon.py [-h] [--ip IP] [--ports PORTS] [--rate {500,1000}] [--file]
                [--verbose] [--version]

Recon Scan

optional arguments:
  -h, --help            show this help message and exit
  --ip IP, -i IP        ip address to scan
  --ports PORTS, -p PORTS
                        port range to scan, example 0-443 or 22,135,443
  --rate {500,1000}, -r {500,1000}
                        rate for masscan packets, default 500, max 1000
  --file                output nmap results to a text file
  --verbose             print more results to console
  --version, -v         show program's version number and exit
```

## port-tester.py

Simple script to test if a port is open on a host.  

```console
$ ./port-tester.py --ip 192.168.8.8 --port 53

$ ./port-tester.py -h
Port Tester, tests if a port is open on an IP
usage: port-tester.py [-h] [--ip IP] [--port PORT] [--file] [--version]

Port Tester Script

optional arguments:
  -h, --help            show this help message and exit
  --ip IP, -i IP        ip address to test
  --port PORT, -p PORT  port to test
  --file                output results to a text file
  --version, -v         show program's version number and exit
```

## Author

[M. Beauchamp](https://github.com/beauchompers)
