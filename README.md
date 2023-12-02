# DNS Flow Monitor

## Intro

DNS Flow Monitor is a simple utility to print DNS query / response flows in real time. The utility can capture both UDP and TCP DNS traffic. User can press `Ctrl-C` to stop the utility running. User can also check packet details by using `--debug` option.

The utility DOES NOT show mDNS traffic.

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
usage: dns-flow.py [-h] --interface INTERFACE [--debug]

DNS Flow Monitor - Scapy Version

optional arguments:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Interface used to capture DNS traffic (interfaces: ['lo', 'eth0'])
  --debug               Display raw packet details

===== OUTPUT FORMAT (without debug flag) =====

QUERY:
[UTC TIMESTAMP] [PROTOCOL] QUERY [Tx ID] [RCODE TEXT] [QUERY NAME] [QUERY TYPE TEXT]

RESPONSE (RCODE == 0):
[UTC TIMESTAMP] [PROTOCOL] RESPONSE [Tx ID] [RCODE TEXT] [RESPONSE RR NAME] [RESPONSE RR TYPE TEXT] [RESPONSE RR TTL] [RESPONSE RESOURCE DATA]
    
RESPONSE (RCODE != 0):
[UTC TIMESTAMP] [PROTOCOL] RESPONSE [Tx ID] [RCODE TEXT]
```

## Output Format

Every DNS traffic transaction will be printed in one line. Each field is separated by a tab. There are 3 different output format.

### QUERY Traffic Output Format

```
[UTC TIMESTAMP] [PROTOCOL] QUERY [Tx ID] [RCODE TEXT] [QUERY NAME] [QUERY TYPE TEXT]

Example:

Mon, 04 Apr 2022 05:23:00 +0000	UDP	QUERY	8679	NoError	www.pinterest.com.	A
```

| Field Name | Description |
| --- | --- |
| UTC TIMESTAMP | UTC timestamp |
| PROTOCOL | UDP or TCP |
| Tx ID | Transaction ID |
| RCODE TEXT | Response Code text |
| QUERY NAME | Query Name |
| QUERY TYPE TEXT | Query Type |

### RESPONSE Traffic Output Format

#### RCODE == 0

```
[UTC TIMESTAMP] [PROTOCOL] RESPONSE [Tx ID] [RCODE TEXT] [RESPONSE RR NAME] [RESPONSE RR TYPE TEXT] [RESPONSE RR TTL] [RESPONSE RESOURCE DATA]

Example:

Mon, 04 Apr 2022 05:23:00 +0000	UDP	RESPONSE	8679	NoError	www.pinterest.com.	CNAME	3358	www-pinterest-com.gslb.pinterest.com.
```

| Field Name | Description |
| --- | --- |
| UTC TIMESTAMP | UTC timestamp |
| PROTOCOL | UDP or TCP |
| Tx ID | Transaction ID |
| RCODE TEXT | Response Code text |
| RESPONSE RR NAME | Resource Record Name of DNS Response |
| RESPONSE RR TYPE TEXT | Resource Record Type of DNS Response |
| RESPONSE RR TTL | Resource Record TTL of DNS Response |
| RESPONSE RESOURCE DATA | Resource Data of DNS Response |

Please note that some responses from particular RR types(e.g. SRV) might not have RDATA field. In this case, the `RESPONSE RESOURCE DATA` field would be `NO_RDATA`.

#### RCODE != 0

```
[UTC TIMESTAMP] [PROTOCOL] RESPONSE [Tx ID] [RCODE TEXT]

Example:

Mon, 04 Apr 2022 05:25:22 +0000	UDP	RESPONSE	30045	NXDomain
```

| Field Name | Description |
| --- | --- |
| UTC TIMESTAMP | UTC timestamp |
| PROTOCOL | UDP or TCP |
| Tx ID | Transaction ID |
| RCODE TEXT | Response Code text |

## Example

```
$ sudo ./dns-flow.py --interface wlp0s20f3
Mon, 04 Apr 2022 05:22:53 +0000	UDP	QUERY	55525	NoError	slack.com.	AAAA
Mon, 04 Apr 2022 05:22:53 +0000	UDP	QUERY	43350	NoError	slack.com.	A
Mon, 04 Apr 2022 05:22:53 +0000	UDP	QUERY	28481	NoError	slack.com.	A
Mon, 04 Apr 2022 05:22:53 +0000	UDP	QUERY	15671	NoError	slack.com.	AAAA
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	44.237.180.172
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	52.89.90.67
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	44.234.235.93
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	35.82.91.193
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	54.245.50.245
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	54.71.95.193
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	54.70.179.16
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	54.188.33.22
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	28481	NoError	slack.com.	A	15	35.81.85.251
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	54.188.33.22
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	44.237.180.172
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	54.245.50.245
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	35.82.91.193
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	44.234.235.93
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	54.70.179.16
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	35.81.85.251
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	54.71.95.193
Mon, 04 Apr 2022 05:22:53 +0000	UDP	RESPONSE	43350	NoError	slack.com.	A	15	52.89.90.67
Mon, 04 Apr 2022 05:23:00 +0000	UDP	QUERY	8679	NoError	www.pinterest.com.	A
Mon, 04 Apr 2022 05:23:00 +0000	UDP	RESPONSE	8679	NoError	www.pinterest.com.	CNAME	3358	www-pinterest-com.gslb.pinterest.com.
Mon, 04 Apr 2022 05:23:00 +0000	UDP	RESPONSE	8679	NoError	www-pinterest-com.gslb.pinterest.com.	CNAME	203	www.gslb.pinterest.net.
Mon, 04 Apr 2022 05:23:00 +0000	UDP	RESPONSE	8679	NoError	www.gslb.pinterest.net.	CNAME	34	www.pinterest.com.edgekey.net.
Mon, 04 Apr 2022 05:23:00 +0000	UDP	RESPONSE	8679	NoError	www.pinterest.com.edgekey.net.	CNAME	5273	e6449.a.akamaiedge.net.
Mon, 04 Apr 2022 05:23:00 +0000	UDP	RESPONSE	8679	NoError	e6449.a.akamaiedge.net.	A	20	104.86.184.250
...
```

If `--debug` option is enabled, a detailed packet information block will be displayed above the normal traffic flow message line.
