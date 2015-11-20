#!/usr/bin/env python

import time
import nmap
import pexpect
import getpass
import os
import sys
import optparse

if not os.geteuid() == 0:
    sys.exit("[!] Please ensure you are root before you run this")

def get_pi(cidr):
    nm = nmap.PortScanner()
    scan = nm.scan(hosts=cidr, arguments='-sP')
    hosts = nm.all_hosts()
    pi_info = []

    for host in hosts:
        if ('mac' in nm[host]['addresses'] and
                'B8:27:EB' in nm[host]['addresses']['mac']):
            pi_mac = str(nm[host]['addresses']['mac'])
            pi_ip = str(nm[host]['addresses']['ipv4'])
            pi_info = [pi_mac, pi_ip]
            return pi_info
        else:
            pass

def pi_shell(pi_ip):
    username = raw_input('[+] Please enter your username: ')
    password = getpass.getpass('[+] Password for ' + username + ': ')
    connection_string = 'ssh ' + username + '@' + pi_ip

    try:
        print '[*] trying ' + pi_ip + ' right now...'
        
        connect = pexpect.spawn(connection_string)
        
        time.sleep(4)
        
        connect.sendline(password)
        connect.interact()
    except Exception, e:
        print '[!] Failed to reach ' + pi_ip
        print str(e)

def main():
    parser = optparse.OptionParser("usage: locate_pi.py [-n network_address/cidr]")
    parser.add_option('-n', dest='cidr', type='string',\
            help='specify network and cidr eg. 0.0.0.0/24')
    (options, args) = parser.parse_args()
    if options.cidr == None:
        print parser.usage
        exit(0)
    else:
        cidr = options.cidr

    print "[*] Locating pi..."
    
    if get_pi(cidr):
        pi_info = get_pi(cidr)
        
        print '[+] ' + pi_info[0] + ' Found at ' + pi_info[1]
        
        shell = raw_input("[-] Would you like to shell into " +\
                "this pi now? [y/n]: ")
        shell.lower()

        if shell == 'y':
            pi_shell(pi_info[1])
        elif shell == 'n':
            print '[*] Goodbye...'
        else:
            print '[!] ' + shell + ' is not a recognized command,' +\
                    'y or n next time please'
    else:
        print "[!] Unable to locate pi"

if __name__ == "__main__":
    main()
