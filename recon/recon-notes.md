# Name of target

## 1. Subdomain enumerating
- [ ] Run the recon program `./recon-sh` to gather information about targets domain, subdomains, IP-addr and related assets
- [ ] Combine the output from these tools in `scan_path` to create a comphrensive list of potential targets
- [ ] Do not forget to list all ports and services from the `nmap` scan.

## 2. Perform whois and reverse whois lookups
- [ ] whois: For standard WHOIS lookups
- [ ] amass intel: For advanced WHOIS and reverse whois queries
- [ ] SecurityTrails: To find related domains

## 3. Peform additional nmap scanning of the subdomains identified
- [ ] Check for services
- [ ] Check for open-ports
- [ ] Check for filtered ports
- [ ] Create a list to summarise all the findings

## 4. Search for additional domains and applications on Beivgil
- [ ] Visit [bevigil.com](http://bevigil.com) and perform additional searches
- [ ] Check for applications
- [ ] Check for domains
- [ ] Check for general assets

## 5. Use shodan for discovering internet-exposed assets
- [ ] Open ports
- [ ] Misconfigured services
- [ ] Exposed devices
- [ ] Vulnerable software version

## 6. Search for github/api secrets:
- [ ] Use truffle hog
- [ ] Use git-secrets
- [ ] Perform searches on Github like:
```
   org:[organization_name] filename:config
   org:[organization_name] password
   org:[organization_name] key
   ```
- [ ] Review commits and branches for accidentially exposed information

## 7. Directory and file enumeration
- [ ] Search for hidden files or directories using `gobuster` with common wordlist
- [ ] Test several wordlists depending on the context of the application

## Notes 
- [ ] Ask alot of why's.
- [ ] Perform the recon throughly.
- [ ] Allocate sufficent time for bug bounty sessions 
- [ ] Ensure you adhere to program's scope and rules of engagement
- [ ] Document findings carefully and validate any vulnerabilities before reporting
- [ ] Use proper discretion when handling sensitive data such as API keys or credentials


