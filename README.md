# SPFWALKER

Tool to recursively walk SPF records given a target domain. This will walk all related domains in includes and query relevant WHOIS information from all the "includees". Can also save the information into a JSON file.

## Installation

`go get -u github.com/djhohnstein/spfwalker`

## Usage

```
homedir\go> spfwalker.exe -h
Usage of spfwalker.exe:
  -domain string
        Domain to walk and retrieve SPF records for.
  -outfile string
        File to save JSON results to.
```

## Example

```
.\spfwalker.exe -domain tesla.com

Domain: tesla.com (5 includes, 14 ip4)
        [Include] spf.protection.outlook.com
        [Include] mail.zendesk.com
        [Include] _spf.salesforce.com
        [Include] _spfsn.teslamotors.com
        [Include] _spf.qualtrics.com
        [IP4]     149.96.231.186
        [IP4]     149.96.247.186
        [IP4]     148.163.155.1
        [IP4]     148.163.151.57
        [IP4]     209.11.133.122
        [IP4]     13.111.88.1
        [IP4]     13.111.88.2
        [IP4]     13.111.88.52
        [IP4]     13.111.88.53
        [IP4]     13.111.62.118
        [IP4]     94.103.153.130
        [IP4]     82.199.68.176/28
        [IP4]     95.172.66.176/28
        [IP4]     51.163.163.128/25

        Whois Information
                [CN]         *.service-now.com
                [IPv4]       149.96.247.186
                [Name]       SERVICENOW, INC.
                [HostName]   vip-149-96-247-186.cust.service-now.com.
                [SearchTerm] 149.96.247.186

        Whois Information
                [CN]         *.service-now.com
                [IPv4]       149.96.231.186
                [Name]       SERVICENOW, INC.
                [HostName]   vip-149-96-231-186.cust.service-now.com.
                [SearchTerm] 149.96.231.186

        Whois Information
                [CN]         *.calero.com
                [IPv4]       94.103.153.130
                [Name]       RIPE Network Coordination Centre
                [HostName]   mail.ab-groep.nl.
                [SearchTerm] 94.103.153.130

... snip ...
```