#!/usr/bin/env python3

import argparse
import os
from scapy.all import get_working_ifaces,sniff,DNS,DNSQR,DNSRR
import sys
import time

def get_interfaces():
    interfaces = []

    for interface in get_working_ifaces():
        if_name = interface.name

        interfaces.append(if_name)

    return interfaces

def process_payload(packet):
    rcode_def = {
        0: 'NoError',
        1: 'FormErr',
        2: 'ServFail',
        3: 'NXDomain',
        4: 'NotImp',
        5: 'Refesed',
    }
    
    rr_type_def = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        35: 'NAPTR',
        41: 'OPT',
        48: 'DNSKEY',
        251: 'IXFR',
        252: 'AXFR',
        255: 'ANY',
    }
    
    if packet.haslayer(DNS):
        timestamp = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
        
        dns = packet[DNS]
        dns_qr = dns.getfieldval('qr')
        dns_id = dns.getfieldval('id')
        dns_rcode = dns.getfieldval('rcode')
        dns_rcode_text = rcode_def[dns_rcode]

        # process query
        if dns_qr == 0:
            dns_dnsqr = dns[DNSQR]
            dns_query_name = dns_dnsqr.getfieldval('qname').decode()
            dns_query_type = dns_dnsqr.getfieldval('qtype')
            dns_query_type_text = rr_type_def[dns_query_type]
            
            print(f'{timestamp}\tQUERY\t{dns_id}\t{dns_rcode_text}\t{dns_query_name}\t{dns_query_type_text}')

        # process response
        if dns_qr == 1:
            # only process response if rcode == 0
            if dns_rcode == 0:
                # iterate each answer
                for i in range(dns.ancount):
                    dns_dnsrr = dns.an[i]

                    dns_response_rrname = dns_dnsrr.getfieldval('rrname')
                    if isinstance(dns_response_rrname, bytes):
                        dns_response_rrname = dns_response_rrname.decode()
                    dns_response_type = dns_dnsrr.getfieldval('type')
                    dns_response_type_text = rr_type_def[dns_response_type]
                    dns_response_ttl = dns_dnsrr.getfieldval('ttl')

                    try:
                        dns_response_data = dns_dnsrr.getfieldval('rdata')
                    except AttributeError:
                        dns_response_data = 'NO_RDATA'
                    else:
                        if isinstance(dns_response_data, bytes):
                            dns_response_data = dns_response_data.decode()
                
                    print(f'{timestamp}\tRESPONSE\t{dns_id}\t{dns_rcode_text}\t{dns_response_rrname}\t{dns_response_type_text}\t{dns_response_ttl}\t{dns_response_data}')
            else:
                print(f'{timestamp}\tRESPONSE\t{dns_id}\t{dns_rcode_text}')
            

if __name__ == '__main__':
    interfaces = get_interfaces()
    
    # set up command arguments
    epilog = """
===== OUTPUT FORMAT =====

QUERY:
[UTC TIMESTAMP] QUERY [Tx ID] [RCODE TEXT] [QUERY NAME] [QUERY TYPE TEXT]

RESPONSE (RCODE == 0):
[UTC TIMESTAMP] RESPONSE [Tx ID] [RCODE TEXT] [RESPONSE RR NAME] [RESPONSE RR TYPE TEXT] [RESPONSE RR TTL] [RESPONSE RESOURCE DATA]
    
RESPONSE (RCODE != 0):
[UTC TIMESTAMP] RESPONSE [Tx ID] [RCODE TEXT]
    """
    
    parser = argparse.ArgumentParser(description='DNS Flow Monitor - Scapy Version', epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--interface', type=str, required=True, help=f'Interface used to capture DNS traffic (interfaces: {interfaces})')
    parser.add_argument('--protocol', type=str, required=False, default='udp', help='Protocol(udp/tcp) used to capture DNS traffic (default: udp) TODO: add capability to capture DNS responses over TCP')
    args = parser.parse_args()
    
    # scapy needs superuser permission to capture packets. check EUID and exit if it's not root user
    euid = os.geteuid()
    if euid != 0:
        print('Please run this utility under root user permission.')
        sys.exit(2)

    # check if the passed interface name exists in the running system
    if args.interface not in interfaces:
        print(f'{args.interface} is not a valid interface name.')
        sys.exit(3)

    # check if a proper protocol is specified
    if args.protocol != 'tcp' and args.protocol != 'udp':
        print(f'Unrecogized protocol string {args.protocol}.')
        sys.exit(4)

    # start sniffing DNS traffic
    sniff(iface=args.interface, filter=args.protocol, lfilter=lambda p: process_payload(p))
