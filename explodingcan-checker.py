#!/usr/bin/env python
"""
Checks whether a web server is vulnerable to CVE-2017-7269.

Based on:
 * https://www.exploit-db.com/exploits/41992/
 * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269

Author: Lorenzo Grespan 
License: https://www.gnu.org/licenses/gpl-3.0.en.html

"""
from __future__ import print_function
import argparse
import logging
import re

log = logging.getLogger(__name__)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter())
log.addHandler(sh)
log.setLevel(logging.INFO)

try:
    import requests
except ImportError as e:
    raise SystemExit("Could not find the 'request' package.")


class NotATarget(Exception):
    pass


def scan(target, timeout=None, username=None, password=None):
    try:
        r = requests.options(target,
                             timeout=timeout,
                             auth=(username, password))
    except requests.exceptions.RequestException as e:
        raise NotATarget(e)

    if r is None:
        raise NotATarget("Target did not return any HTTP headers. Aborting.")
    headers = r.headers
    log.debug("Headers:\n{}\n".format(repr(headers)))

    # if it's not IIS 6.0
    if 'IIS/6.0' not in headers.get('Server', ''):
        log.debug("Not an IIS/6.0 server.")
        return False

    # WebDAV checks, according to the metasploit module any would work

    if headers.get('MS-Author-Via') == 'DAV':
        return True

    if headers.get('DASL') == '<DAV:sql>':
        return True

    if re.match(r'/^[1-9]+(,\s+[1-9]+)?$/', headers.get('DAV', "")):
        return True

    if 'PROPFIND' in headers.get('Public', ""):
        return True

    if 'PROPFIND' in headers.get('Allow', ""):
        return True

    # in doubt, return False
    return False


def main():
    parser = argparse.ArgumentParser()
    #
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('-t', '--target', help="A single target")
    g.add_argument('-f', '--file', type=argparse.FileType(),
                   help="A file with a list of targets")
    #
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('--timeout', type=float,
                        help="Timeout for connecting to a target")
    parser.add_argument('--username', help="Username for authentication")
    parser.add_argument('--password', help="Password for authentication")
    parser.add_argument('--bw', action='store_true',
                        help="Suppress colours in output")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    if args.target is None and args.file is not None:
        targets = args.file.read().splitlines()
    elif args.target is not None:
        targets = (args.target, )

    for t in targets:
        print("Trying {}... ".format(t), end='')
        try:
            result = scan(t, args.timeout, args.username, args.password)
        except KeyboardInterrupt:
            raise SystemExit("User cancelled")
        except NotATarget as e:
            log.debug(e)
            print("returned an error".format(t))
            continue

        if result is True:
            if args.bw:
                print("vulnerable.".format(t))
            else:
                print("\033[92m vulnerable\033[0m.".format(t))
        else:
            print("not vulnerable.".format(t))


if __name__ == '__main__':
    main()
