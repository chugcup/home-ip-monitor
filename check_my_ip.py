#!/usr/bin/env python3

#############################################################################
# External IP Address Monitor
#
# Reach out to remote IP Address services to determine external IP address.
# Helpful for monitoring external IP if DNS entries need to be updated.
#############################################################################
# Author: Jeff Gordon (2022)
# Version 1.0
#############################################################################

import argparse
import datetime
import ipaddress
import json
import os
import re
import smtplib
import sys
import urllib.request

# For resources that reject non-standard User-Agents, set a real one here
USER_AGENT_STRING = "Mozilla/5.0 (Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0"


### Resources/Parsers #############################################################################

## - ipify.org
# NOTE: IPv4-only (use `api64.ipify.org` for both)
SOURCE_IPIFY_ORG_URL = "https://api.ipify.org?format=json"
def request_ipify_org():
    req = urllib.request.Request(SOURCE_IPIFY_ORG_URL)
    resp = urllib.request.urlopen(req)
    if resp.status != 200:
        raise RuntimeError(f"IP request returned unexpected error code: {resp.status}")
    return resp.read().decode('utf-8')

def parse_ipify_org(data):
    # Nice JSON API resource
    # { "ip": <IP STRING> }
    return json.loads(data)['ip']


## - whatismyip.org
SOURCE_WHATISMYIP_ORG_URL = "https://whatismyip.org"
def request_whatismyip_org():
    # Denies non-standard User-Agent requests (403)
    headers_dict = {"User-Agent": USER_AGENT_STRING}
    req = urllib.request.Request(SOURCE_WHATISMYIP_ORG_URL, headers=headers_dict)
    resp = urllib.request.urlopen(req)
    if resp.status != 200:
        raise RuntimeError(f"IP request returned unexpected error code: {resp.status}")
    return resp.read().decode('utf-8')

def parse_whatismyip_org(data):
    # HTML results
    SEARCH_PATTERN = r'<strong>Your IP:</strong>\s*<a href=".*?">([0-9\.:]+)</a>'
    try:
        return re.search(SEARCH_PATTERN, data).group(1)
    except AttributeError:
        pass

###################################################################################################


# Request/parser options for public IP address resource
IP_SOURCE_OPTIONS = {
    'ipify': {
        'name': "https://api.ipify.org",
        'url': SOURCE_IPIFY_ORG_URL,
        'request': request_ipify_org,
        'parser': parse_ipify_org
    },
    'whatismyip': {
        'name': "https://whatismyip.org",
        'url': SOURCE_WHATISMYIP_ORG_URL,
        'request': request_whatismyip_org,
        'parser': parse_whatismyip_org
    },
}
DEFAULT_IP_SOURCE = 'ipify'


def main(source, compare_file=None, gmail_settings=None, test_gmail=False, verbose=False, quiet=False):
    # Perform Gmail test notification
    # - Simple settings verification check; script will not proceed past this block
    if test_gmail:
        if not gmail_settings:
            print("[ERROR] Missing required '--gmail' argument for e-mail notification test", file=sys.stderr)
            sys.exit(1)
        print("Sending test e-mail...")
        try:
            success = relay_gmail_notification("127.0.0.1", "127.0.0.2", gmail_settings)
        except Exception as e:
            print(f"[ERROR] Error while attempting to send test Gmail notification: {str(e)}", file=sys.stderr)
            success = False
        if success:
            print("Success")
            sys.exit(0)  # Success
        else:
            print("Failure")
            sys.exit(1)  # Error

    if source not in IP_SOURCE_OPTIONS:
        raise ValueError(f"Invalid source option: '{source}'")

    source_name = IP_SOURCE_OPTIONS[source]['name']
    source_request = IP_SOURCE_OPTIONS[source]['request']
    source_parser = IP_SOURCE_OPTIONS[source]['parser']

    # Check for previous comparison file and parse IP address
    orig_ip = None
    compare_filepath = None
    if compare_file is not None:
        compare_filepath = os.path.abspath(compare_file)
        if os.path.exists(compare_filepath):
            if not os.path.isfile(compare_filepath):
                print(f"[ERROR] IP compare path exists but is not a file: {compare_filepath}", file=sys.stderr)
                sys.exit(1)  # Don't proceed
            try:
                with open(compare_filepath, 'r') as f:
                    orig_ip_str = f.read().strip()
                orig_ip = ipaddress.ip_address(orig_ip_str)
            except Exception as e:
                print(f"[ERROR] Failed to read original IP address from compare file: {str(e)}", file=sys.stderr)
                sys.exit(1)  # Don't proceed

    # Fetch current IP address from indicated resource
    req_data = source_request()
    new_ip_str = source_parser(req_data)

    # Print results
    if verbose:
        # Verbose output (Source + IP)
        print(f"Source:     {source_name}")
        print(f"Current IP: {new_ip_str}")
    elif not quiet:
        # Default output (IP only)
        print(new_ip_str, end='')

    # Compare to original IP from compare file
    if compare_filepath:
        if orig_ip is not None:
            if ipaddress.ip_address(new_ip_str) != orig_ip:
                if verbose:
                    print(f"** IP Address change detected (OLD: {str(orig_ip)})")
                # Send e-mail notification
                if gmail_settings:
                    try:
                        success = relay_gmail_notification(orig_ip, new_ip_str, gmail_settings)
                    except Exception as e:
                        print(f"[ERROR] Error while attempting to send Gmail notification: {str(e)}", file=sys.stderr)
            else:
                return  # NOTE: Break here to avoid updating 'compare_file' (if no change)

        # Write result to compare file
        with open(compare_filepath, 'w') as f:
            f.write(new_ip_str)


def relay_gmail_notification(old_ip, new_ip, gmail_settings):
    """
    Use Gmail relay settings to send notification e-mail of IP change.

    In the future this may be substituted for a more general e-mail notification
    approach; for now, using Gmail with basic login information is the simplest
    way to generate e-mail notifications that don't get filtered.

    At this time, Gmail requires using the "App passwords" feature to generate
    a randomized password since our script can't use 2-Step Verification.
    This value goes in the `email_password` setting field.
    """
    cur_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    gmail_settings_path = os.path.abspath(gmail_settings)
    gmail_json = None
    with open(gmail_settings_path, 'r') as f:
        gmail_json = json.loads(f.read())

    for field in ["email_from", "email_password", "email_to", "email_subject"]:
        if field not in gmail_json:
            raise KeyError(f"Missing required field '{field}' in Gmail settings")

    # Ensure 'To' field is a list
    if not isinstance(gmail_json['email_to'], list):
        gmail_json['email_to'] = [gmail_json['email_to']]

    # Begin generating e-mail
    message_body = f"""The external IP address from a server you are monitoring has changed.

OLD: {old_ip}
NEW: {new_ip}

TIME: {cur_time}
"""
    email_text = f"""From: {gmail_json['email_from']}
To: {','.join(gmail_json['email_to'])}
Subject: {gmail_json['email_subject']}

{message_body}"""

    # Send e-mail
    # TODO: CC / BCC
    # TODO: HTML content
    # TODO: Body template
    try:
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_server.ehlo()
        smtp_server.login(gmail_json['email_from'], gmail_json['email_password'])
        smtp_server.sendmail(
            gmail_json['email_from'],
            gmail_json['email_to'],
            email_text
        )
        smtp_server.close()
    except Exception as e:
        print(f"[ERROR] Failed to send notification e-mail via Gmail: {str(e)}", file=sys.stderr)
        return False

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""Check current external IP address of system.

By default, will print only the detected external IP address.
To increase verbosity, use the `--verbose` flag.

To monitor IP address changes, provide a `-c/--compare` file path to maintain
state between program runs.

    check_my_ip.py --compare ip.txt --verbose

If the previous IP does not match the new IP value, a message will be printed.

In order to notify when an IP change occurs, use the `--gmail` argument with
the path to a JSON settings file.  This file should contain necessary Gmail
server settings information used to relay an e-mail from a valid Gmail address.

    {
      "email_from": "sender@gmail.com",
      "email_password": "hunter2",
      "email_to": "recipient@gmail.com",
      "email_subject": "IP Address Change Detected"
    }

You can test the `--gmail` settings by running the script with the `--test-gmail`
option, which will attempt to send a test e-mail and exit promptly.
""", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', dest='source', default=DEFAULT_IP_SOURCE,
                        choices=list(IP_SOURCE_OPTIONS.keys()),
                        help=f"Remote resource to query for IP address [default='{DEFAULT_IP_SOURCE}']")
    parser.add_argument('-c', '--compare', dest='compare_file', metavar="PATH",
                        help="State file to compare and detect IP address changes")
    parser.add_argument('--gmail', dest='gmail_settings', metavar="SETTINGS",
                        help="Settings file (JSON) containing Gmail relay information")
    parser.add_argument('--test-gmail', dest='test_gmail', action="store_true",
                        help="Debug option to test sending e-mail notification using Gmail relay information")
    verbose_group = parser.add_mutually_exclusive_group()
    verbose_group.add_argument('-v', '--verbose', dest='verbose', action="store_true",
                               help="Verbose output")
    verbose_group.add_argument('-q', '--quiet', dest='quiet', action="store_true",
                               help="Don't print output on success")
    args = parser.parse_args()
    main(source=args.source, compare_file=args.compare_file,
         gmail_settings=args.gmail_settings, test_gmail=args.test_gmail,
         verbose=args.verbose, quiet=args.quiet)
