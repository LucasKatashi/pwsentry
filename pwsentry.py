#!/usr/bin/env python3
from ldap3 import NTLM, ALL, SUBTREE, BASE
from argparse import ArgumentParser
from rich.console import Console
import ldap3
import os

console = Console()

def banner():
    art = '''
 _____       _____         _
|  _  |_ _ _|   __|___ ___| |_ ___ _ _
|   __| | | |__   | -_|   |  _|  _| | |
|__|  |_____|_____|___|_|_|_| |_| |_  |
                                  |___|
                        by: katashi 🇨🇳'''
    return art

def get_ip_addresses(ip_arg):
    if os.path.isfile(ip_arg):
        try:
            with open(ip_arg, 'r') as file:
                ips = [line.strip() for line in file if line.strip()]
            console.print(f'[[blue]INFO[/blue]] Loaded {len(ips)} IP addresses from file: {ip_arg}')
            return ips
        except Exception as e:
            console.print(f'[[red]ERR[/red]] Error reading IP file {ip_arg}: {e}')
            exit(1)
    else:
        return [ip_arg]

def forceChangePassword(ip, netbios, owned_user, password, base_dn, wordlist, target_user):
    server = ldap3.Server(ip, get_info=ALL)
    conn = ldap3.Connection(server, user='{}\\{}'.format(netbios, owned_user), password=password, authentication=NTLM)

    if not conn.bind():
        console.print(f'[[red]ERR[/red]] Error connecting to LDAP server: [red]{conn.result}[/red]')
        exit(1)

    if target_user:
        search_filter = '(&(objectClass=user)(|(sAMAccountName={0})(cn={0})))'.format(target_user)
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=['distinguishedName'])

        if conn.entries:
            user_dn = conn.entries[0].distinguishedName.value

            conn.search(search_base=user_dn, search_filter='(objectClass=*)', search_scope=BASE, attributes=['allowedAttributesEffective'])

            if conn.entries:
                allowed_attrs = conn.entries[0]['allowedAttributesEffective']
                if 'pwdLastSet' in allowed_attrs:
                    console.print(f'[[green]OK[/green]] User {owned_user} can change user [underline]{target_user}[/underline] password. ([yellow]pwned![/yellow])')
                else:
                    console.print(f'[[red]ERR[/red]] User {owned_user} cannot change user {target_user} password.')
            else:
                console.print(f'[[orange]INFO[/orange]] Unable to get {target_user} attributes.')
        else:
            console.print(f'[[blue]INFO[/blue]] User {target_user} not found.')

    if wordlist:
        with open(wordlist, 'r') as file:
            users = [line.strip() for line in file if line.strip()]

        for user in users:
            search_filter = '(&(objectClass=user)(|(sAMAccountName={0})(cn={0})))'.format(user)
            conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=['distinguishedName'])

            if conn.entries:
                user_dn = conn.entries[0].distinguishedName.value

                conn.search(search_base=user_dn, search_filter='(objectClass=*)', search_scope=BASE, attributes=['allowedAttributesEffective'])

                if conn.entries:
                    allowed_attrs = conn.entries[0]['allowedAttributesEffective']
                    if 'pwdLastSet' in allowed_attrs:
                        console.print(f'[[green]OK[/green]] User {owned_user} can change user [underline]{user}[/underline] password. ([yellow]pwned![/yellow])')
                    else:
                        console.print(f'[[red]ERR[/red]] User {owned_user} cannot change user {user} password.')
                else:
                    console.print(f'[[orange]INFO[/orange]] Unable to get {user} attributes.')
            else:
                console.print(f'[[blue]INFO[/blue]] User {user} not found.')
    conn.unbind()

if '__main__' == __name__:
    parser = ArgumentParser(description='ForceChangePassword checker.')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist containing usernames (one per line)')
    parser.add_argument('-t', '--target_user', help='Single target username')
    parser.add_argument('-i', '--ip', required=True, help='Single IP address or path to file containing IP addresses (one per line)')
    parser.add_argument('-u', '--user', required=True, help='Username to use for authentication')
    parser.add_argument('-d', '--domain', required=True, help='FQDN domain to use for authentication')
    parser.add_argument('-p', '--password', required=True, help='Password to use for authentication')

    console.print(f'[purple]{banner()}[/purple]')

    args = parser.parse_args()

    if not (args.wordlist or args.target_user):
        console.print(f'[red][ERR][/red] Use --wordlist or --target_user.')
        exit(1)

    parts = args.domain.split('.')

    netbios = parts[0].upper()
    base_dn = ','.join('DC=' + part for part in parts)

    ip_addresses = get_ip_addresses(args.ip)

    for ip in ip_addresses:
        console.print(f'[[yellow]INFO[/yellow]] Testing IP: {ip}')
        try:
            forceChangePassword(ip, netbios, args.user, args.password, base_dn, args.wordlist, args.target_user)
        except EOFError:
            console.print(f'[[red]ERR[/red]] EOFError for IP {ip}:\n {EOFError}')
            continue
        except KeyboardInterrupt:
            console.print(f'[[red]ERR[/red]] Keyboard interrupt.')
            exit(1)
        except Exception as e:
            console.print(f'[[red]ERR[/red]] Error with IP {ip}: {e}')
            continue