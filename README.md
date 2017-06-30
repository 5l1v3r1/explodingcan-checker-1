# ExplodingCan Checker

Checks whether a web server is vulnerable to CVE-2017-7269.

## UPDATE ##

After Microsoft decided to patch this vulnerability, **this script no longer works**: due to the nature of the checks done, it will report a false positive (vulnerable server) even if the server is not. 

More details: https://www.secarma.co.uk/wannacry-what-is-next/

----

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
