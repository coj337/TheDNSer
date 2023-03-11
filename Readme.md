# TheDNS
TheDNS is a DNS brute forcing tool and is intended as a simple replacement for MassDNS.

## Features
*Fast* DNS brute-forcing without any external dependancies.
Coming Soon: Validation and wildcard filtering

## Performance
DNS Brute-Forcing a list of 30,000 subdomains, the tool outperforms MassDNS based tools.
```
PureDNS Benchmark:
	30,000 records | 25 seconds
    650,000 records | 1 minute, 16 seconds
TheDNS Benchmark:
	30,000 records | 6 seconds
	650,000 records | 1 minute, 17 seconds
```
Note: PureDNS was run with --skip-validation --skip-wildcard-filter and the same resolvers for a 1:1 comparison.


## Getting Started
