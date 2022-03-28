# DNS Flow Monitor

## Intro

DNS Flow Monitor is a simple utility to print DNS query / response flows in real time. The utility is capturing UDP DNS traffic by default. User can press `Ctrl-C` to stop the utility running.

## Python Module Dependencies

Following Python modules are needed to run this utility:

```
argparse
os
scapy
sys
time
```

## Usage

```
$ ./dns-flow.py -h
usage: dns-flow.py [-h] --interface INTERFACE [--protocol PROTOCOL]

DNS Flow Monitor - Scapy Version

options:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Interface used to capture DNS traffic (interfaces: ['lo', 'enp0s31f6', 'wlp0s20f3', 'virbr0'])
  --protocol PROTOCOL   Protocol(udp/tcp) used to capture DNS traffic (default: udp) TODO: add capability to capture DNS responses over TCP

===== OUTPUT FORMAT =====

QUERY:
[UTC TIMESTAMP] QUERY [Tx ID] [RCODE TEXT] [QUERY NAME] [QUERY TYPE TEXT]

RESPONSE (RCODE == 0):
[UTC TIMESTAMP] RESPONSE [Tx ID] [RCODE TEXT] [RESPONSE RR NAME] [RESPONSE RR TYPE TEXT] [RESPONSE RR TTL] [RESPONSE RESOURCE DATA]
    
RESPONSE (RCODE != 0):
[UTC TIMESTAMP] RESPONSE [Tx ID] [RCODE TEXT]
```

## Output Format

Every DNS traffic transaction will be printed in one line. Each field is separated by a tab. There are 3 different output format.

### QUERY Traffic Output Format

```
[UTC TIMESTAMP] QUERY [Tx ID] [RCODE TEXT] [QUERY NAME] [QUERY TYPE TEXT]

Example:

Sun, 27 Mar 2022 16:50:41 +0000 QUERY   50195   NoError quantcast584928381.s.moatpixel.com.     AAAA
```

| Field Name | Description |
| --- | --- |
| UTC TIMESTAMP | UTC timestamp |
| Tx ID | Transaction ID |
| RCODE TEXT | Response Code text |
| QUERY NAME | Query Name |
| QUERY TYPE TEXT | Query Type |

### RESPONSE Traffic Output Format

#### RCODE == 0

```
[UTC TIMESTAMP] RESPONSE [Tx ID] [RCODE TEXT] [RESPONSE RR NAME] [RESPONSE RR TYPE TEXT] [RESPONSE RR TTL] [RESPONSE RESOURCE DATA]

Example:

Mon, 28 Mar 2022 01:51:51 +0000 RESPONSE        58622   NoError fedoraproject.org.      AAAA    42      2605:bc80:3010:600:dead:beef:cafe:fed9
```

| Field Name | Description |
| --- | --- |
| UTC TIMESTAMP | UTC timestamp |
| Tx ID | Transaction ID |
| RCODE TEXT | Response Code text |
| RESPONSE RR NAME | Resource Record Name of DNS Response |
| RESPONSE RR TYPE TEXT | Resource Record Type of DNS Response |
| RESPONSE RR TTL | Resource Record TTL of DNS Response |
| RESPONSE RESOURCE DATA | Resource Data of DNS Response |

Please note that some responses from particular RR types(e.g. SRV) might not have RDATA field. In this case, the `RESPONSE RESOURCE DATA` field would be `NO_RDATA`.

#### RCODE != 0

```
[UTC TIMESTAMP] RESPONSE [Tx ID] [RCODE TEXT]

Example:

Sun, 27 Mar 2022 16:58:50 +0000 RESPONSE        36213   NXDomain
```

| Field Name | Description |
| --- | --- |
| UTC TIMESTAMP | UTC timestamp |
| Tx ID | Transaction ID |
| RCODE TEXT | Response Code text |

## Example

```
$ sudo ./dns-flow.py --interface wlp0s20f3
Mon, 28 Mar 2022 04:01:21 +0000	QUERY	10928	NoError	play.google.com.	AAAA
Mon, 28 Mar 2022 04:01:21 +0000	QUERY	51439	NoError	play.google.com.	A
Mon, 28 Mar 2022 04:01:21 +0000	QUERY	34673	NoError	play.google.com.	AAAA
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	34673	NoError	play.google.com.	AAAA	192	2607:f8b0:4002:806::200e
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	10928	NoError	play.google.com.	AAAA	192	2607:f8b0:4002:806::200e
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	51439	NoError	play.google.com.	A	149	74.125.21.102
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	51439	NoError	play.google.com.	A	149	74.125.21.113
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	51439	NoError	play.google.com.	A	149	74.125.21.100
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	51439	NoError	play.google.com.	A	149	74.125.21.139
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	51439	NoError	play.google.com.	A	149	74.125.21.101
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	51439	NoError	play.google.com.	A	149	74.125.21.138
Mon, 28 Mar 2022 04:01:21 +0000	QUERY	44781	NoError	mail.yahoo.com.	A
Mon, 28 Mar 2022 04:01:21 +0000	QUERY	59557	NoError	mail.yahoo.com.	AAAA
Mon, 28 Mar 2022 04:01:21 +0000	QUERY	23767	NoError	mail.yahoo.com.	A
Mon, 28 Mar 2022 04:01:21 +0000	QUERY	27461	NoError	mail.yahoo.com.	AAAA
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	44781	NoError	mail.yahoo.com.	CNAME	191	edge.gycpi.b.yahoodns.net.
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	44781	NoError	edge.gycpi.b.yahoodns.net.	A	12	69.147.88.7
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	44781	NoError	edge.gycpi.b.yahoodns.net.	A	12	69.147.88.8
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	23767	NoError	mail.yahoo.com.	CNAME	191	edge.gycpi.b.yahoodns.net.
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	23767	NoError	edge.gycpi.b.yahoodns.net.	A	12	69.147.88.8
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	23767	NoError	edge.gycpi.b.yahoodns.net.	A	12	69.147.88.7
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	27461	NoError	mail.yahoo.com.	CNAME	171	edge.gycpi.b.yahoodns.net.
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	27461	NoError	edge.gycpi.b.yahoodns.net.	AAAA	11	2001:4998:18:800::4003
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	27461	NoError	edge.gycpi.b.yahoodns.net.	AAAA	11	2001:4998:18:800::4002
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	59557	NoError	mail.yahoo.com.	CNAME	171	edge.gycpi.b.yahoodns.net.
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	59557	NoError	edge.gycpi.b.yahoodns.net.	AAAA	11	2001:4998:18:800::4003
Mon, 28 Mar 2022 04:01:21 +0000	RESPONSE	59557	NoError	edge.gycpi.b.yahoodns.net.	AAAA	11	2001:4998:18:800::4002
...
```

## Notes

1. This utility cannot parse responses that are using DNS over TCP. This feature will be added later.
