# External IP Address Monitor

Python script for monitoring external IP address (for changes).


# Why

I have a register DNS name I would like to keep updated for development web services
and a home VPN, and my ISP occasionally changes it.  I wrote this script to periodically
query my external IP and notify me if it changes.

## But Dynamic DNS Exists...

Yeah, I known DDNS is largely a solved problem (and a direct monitor solution even exists for [GoDaddy DNS Updates](https://www.instructables.com/Quick-and-Dirty-Dynamic-DNS-Using-GoDaddy/)),
but I wanted to put something together that would do general e-mail notifications so you might
be able to update any DNS service.  It could also be used in the event you _don't_ have a
registered DNS name and are remotely accessing resources by IP address like a caveman.


# Requirements

This script requires Python 3.6 or higher.  No other dependencies are needed.


# Usage

In its basic form, the script will just query and print your current IP address.

    > python3 check_my_ip.py
    172.30.1.1

Use the `-v/--verbose` option to print a little more information.

    > python3 check_my_ip.py --verbose
    Source:     https://api.ipify.org
    Current IP: 172.30.1.1

You can also keep the script quiet (on success) with the `-q/--quiet` flag.

    > python3 check_my_ip.py --quiet
    # Nothing...

## Monitoring Changes

To remember the external address and compare it on future runs, using the `-c/--compare` argument
with a file path.  This does not need to exist the first time the script run, but must be a writable path.

    > python3 check_my_ip.py --verbose --compare=/path/to/ip.txt
    Source:     https://api.ipify.org
    Current IP: 172.30.1.1

On subsequent runs, if the IP changes it will print a message

    > python3 check_my_ip.py --verbose --compare=/path/to/ip.txt
    Source:     https://api.ipify.org
    Current IP: 172.30.1.2
    ** IP Address change detected (OLD: 172.30.1.1)

## E-mail Notification

**Currently only supports Gmail relay**

To be notified by e-mail when your system's IP address changes, you need to create a JSON settings
file with e-mail server information.  The following keys are expected:

    {
      "email_from": "sender@gmail.com",
      "email_password": "PASSWORD",
      "email_to": "recipient@gmail.com",
      "email_subject": "IP Address Change Detected"
    }

**NOTE:** The `email_to` field can be a list of e-mail addresses.

**NOTE:** Google nowadays requires you to use [App Passwords](https://support.google.com/accounts/answer/185833)
when setting up account access for scripts and services without 2-Step Verification.

This settings file path is provided to the script using the `--gmail` argument.

    > python3 check_my_ip.py --verbose --compare=/path/to/ip.txt --gmail=/path/to/gmail.json
    Source:     https://api.ipify.org
    Current IP: 172.30.1.2

You can verify your Gmail settings by using the `--test-gmail` argument, which will simply
send a test e-mail using the provided settings and exit.

    > python3 check_my_ip.py --gmail=/path/to/gmail.json --test-gmail


# Scheduled Runs

The most basic way to schedule this is with a `crontab` configuration:

    # External IP Monitor
    0 */6 * * * root /home/user/check_my_ip.py --quiet --compare=/home/user/external_ip.txt --gmail=/home/user/gmail.json

The example above will run every 6 hours.
