# ExplodingCan Checker

Checks whether a web server is vulnerable to CVE-2017-7269.

Based on:
 * https://www.exploit-db.com/exploits/41992/
 * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269

Author: Lorenzo Grespan  
License: https://www.gnu.org/licenses/gpl-3.0.en.html  

# Usage:

```
usage: explodingcan-checker.py [-h] (-t TARGET | -f FILE) [-d]
                               [--timeout TIMEOUT] [--username USERNAME]
                               [--password PASSWORD] [--bw]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        A single target
  -f FILE, --file FILE  A file with a list of targets
  -d, --debug
  --timeout TIMEOUT     Timeout for connecting to a target
  --username USERNAME   Username for authentication
  --password PASSWORD   Password for authentication
  --bw                  Suppress colours in output
```
