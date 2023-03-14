# TheDNSer
TheDNSer is a DNS brute forcing tool and is intended as a simple replacement for MassDNS and tools based on MassDNS like PureDNS.

## Features
- *Fast* DNS brute-forcing without any external dependencies.
- Coming Soon: Validation and wildcard filtering

## Performance
DNS Brute-Forcing a list of 30,000 subdomains, the tool outperforms MassDNS based tools.
```
PureDNS Benchmark:
	30,000 records | 25 seconds
    650,000 records | 1 minute, 16 seconds
TheDNSer Benchmark:
	30,000 records | 6 seconds
	650,000 records | 1 minute, 17 seconds
```
Note: PureDNS was run with --skip-validation --skip-wildcard-filter and the same resolvers for a 1:1 comparison.


## Getting Started
Simply pass the root domain, a file with a list of subdomains to resolve, and a list of resolvers
```
TheDNSer.exe stratussecurity.com subdomain.txt dns_resolvers.txt
```

## Nuget Library
There is a nuget library published as "DNS_Bruteforcer" for using this library natively in another application.
See Program.cs for example library usage.