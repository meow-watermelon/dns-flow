#!/usr/bin/env python3

import argparse
import os
from scapy.all import get_working_ifaces,sniff,DNS,DNSQR,DNSRR,TCP,UDP
import sys
import time

def get_interfaces():
    interfaces = []

    for interface in get_working_ifaces():
        if_name = interface.name

        interfaces.append(if_name)

    return interfaces

def process_payload(packet):
    # DNS RCODEs ref.: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    rcode_def = {
        0: 'NoError',
        1: 'FormErr',
        2: 'ServFail',
        3: 'NXDomain',
        4: 'NotImp',
        5: 'Refesed',
        6: 'YXDomain',
        7: 'YXRRSet',
        8: 'NXRRSet',
        9: 'NotAuth',
        10: 'NotZone',
        11: 'DSOTYPENI',
        16: 'BADVERS / BADSIG',
        17: 'BADKEY',
        18: 'BADTIME',
        19: 'BADMODE',
        20: 'BADNAME',
        21: 'BADALG',
        22: 'BADTRUNC',
        23: 'BADCOOKIE',
    }

    # DNS type ref.: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    rr_type_def = {
        0: "Reserved",
        1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
        9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
        15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN",
        21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
        27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC",
        33: "SRV", 34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6",
        39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP",
        45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
        50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
        56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 60: "CDNSKEY",
        61: "OPENPGPKEY", 62: "CSYNC", 99: "SPF", 100: "UINFO", 101: "UID",
        102: "GID", 103: "UNSPEC", 104: "NID", 105: "L32", 106: "L64", 107: "LP",
        108: "EUI48", 109: "EUI64", 249: "TKEY", 250: "TSIG", 255: "ANY", 256: "URI",
        257: "CAA", 258: "AVC", 32768: "TA", 32769: "DLV", 65535: "RESERVED"
    }
    
    if packet.haslayer(DNS):
        # determine if DNS upper layer is UDP or TCP
        if packet.haslayer(UDP):
            dns_upper_layer = 'UDP'

        if packet.haslayer(TCP):
            dns_upper_layer = 'TCP'

        # set up timestamp
        timestamp = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())

        # retrieve common fields
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
            
            print(f'{timestamp}\t{dns_upper_layer}\tQUERY\t{dns_id}\t{dns_rcode_text}\t{dns_query_name}\t{dns_query_type_text}')

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
                
                    print(f'{timestamp}\t{dns_upper_layer}\tRESPONSE\t{dns_id}\t{dns_rcode_text}\t{dns_response_rrname}\t{dns_response_type_text}\t{dns_response_ttl}\t{dns_response_data}')
            else:
                print(f'{timestamp}\t{dns_upper_layer}\tRESPONSE\t{dns_id}\t{dns_rcode_text}')
            

if __name__ == '__main__':
    interfaces = get_interfaces()
    
    # set up command arguments
    epilog = """
===== OUTPUT FORMAT =====

QUERY:
[UTC TIMESTAMP] [PROTOCOL] QUERY [Tx ID] [RCODE TEXT] [QUERY NAME] [QUERY TYPE TEXT]

RESPONSE (RCODE == 0):
[UTC TIMESTAMP] [PROTOCOL] RESPONSE [Tx ID] [RCODE TEXT] [RESPONSE RR NAME] [RESPONSE RR TYPE TEXT] [RESPONSE RR TTL] [RESPONSE RESOURCE DATA]
    
RESPONSE (RCODE != 0):
[UTC TIMESTAMP] [PROTOCOL] RESPONSE [Tx ID] [RCODE TEXT]
    """
    
    parser = argparse.ArgumentParser(description='DNS Flow Monitor - Scapy Version', epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--interface', type=str, required=True, help=f'Interface used to capture DNS traffic (interfaces: {interfaces})')
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

    # start sniffing DNS traffic
    sniff(iface=args.interface, lfilter=lambda p: process_payload(p))
