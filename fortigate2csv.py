#!/usr/bin/env python

# author    dan walker <code@danwalker.com>
# created   2020-11-12
# updated   2020-11-23
# url       github.com/danwalkeruk/fortigate2csv

import argparse
import getpass
import sys
import requests
import json

# disable warnings for insecure connections
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# items
item_types = ['interface', 'policy', 'snat', 'address', 'service', 'dnat', 'pool']

def main():
    # build a parser, set arguments, parse the input
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--firewall', help='Firewall Host', required=True)
    parser.add_argument('-u', '--user', help='Username', required=True)
    parser.add_argument('-v', '--vdom', help='VDOM', required=True)
    parser.add_argument('-i', '--item', help='Item', required=True)
    parser.add_argument('-o', '--outfile', help='Output CSV file', required=False)
    args = parser.parse_args()

    base_url = f'https://{args.firewall}/'

    # check item type
    if args.item not in item_types:
        print(f'Please choose a valid item type: {", ".join(map(str, item_types))}')
        sys.exit(1)

    # use a hidden password entry
    password = getpass.getpass()

    # connect and authenticate
    print(f'Connecting to {args.firewall} ({args.vdom}) as {args.user}')
    f = f_login(args.firewall, args.user, password, args.vdom)
    print('Fetching data...')

    # DNAT and VIPs
    if args.item == 'dnat':
        data = f.get(f'{base_url}api/v2/cmdb/firewall/vip/?vdom={args.vdom}').json()
        headers = ['name', 'extip', 'mappedip', 'extintf', 'arp-reply', 
            'nat-source-vip', 'portforward', 'srcintf-filter', 'comments']

    # SNAT Mapping
    elif args.item == 'snat':
        data = f.get(f'{base_url}api/v2/cmdb/firewall/central-snat-map/?vdom={args.vdom}').json()
        headers = ['policyid', 'status', 'orig-addr', 'dst-addr', 'srcintf', 'dstintf', 
            'nat', 'nat-ippool', 'comments']

    # addresses
    elif args.item == 'address':
        data = f.get(f'{base_url}api/v2/cmdb/firewall/address/?vdom={args.vdom}').json()
        headers = ['name', 'type', 'subnet', 'fqdn', 'associated-interface', 'visibility', 
            'allow-routing', 'comment']

    # pools
    elif args.item == 'pool':
        data = f.get(f'{base_url}api/v2/cmdb/firewall/ippool/?vdom={args.vdom}').json()
        headers = ['name', 'type', 'startip', 'endip', 'source-startip', 'source-endip', 
        'block-size', 'permit-any-host', 'arp-reply', 'comments']

    # services
    elif args.item == 'service':
        data = f.get(f'{base_url}api/v2/cmdb/firewall.service/custom?vdom={args.vdom}').json()
        headers = ['name', 'category', 'protocol', 'tcp-portrange', 'udp-portrange',
            'visibility', 'comments']

    # interfaces
    elif args.item == 'interface':
        data = f.get(f'{base_url}api/v2/monitor/system/available-interfaces?vdom={args.vdom}').json()
        headers = ['name', 'alias', 'description', 'type', 'is_vdom_link', 'is_system_interface', 
            'is_vlan', 'status', 'role', 'ipv4_addresses', 'vlan_interface', 'vlan_id', 
            'mac_address', 'visibility', 'comments']

    # policies
    elif args.item == 'policy':
        data = f.get(f'{base_url}api/v2/cmdb/firewall/policy?vdom={args.vdom}').json()
        headers = ['policyid', 'name', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'internet-service-id',
            'internet-service-src-id', 'service', 'action', 'status', 'schedule', 'visibility', 
            'profile-group', 'nat', 'comments']
    
    # logout to prevent stale sessions
    print(f'Logging out of firewall')
    f.get(f'https://{args.firewall}/logout', verify=False, timeout=10)
    
    # format the data
    if 'results' not in data:
        print('Firewall returned no results')
        sys.exit(1)
    
    csv_data = build_csv(headers, data['results'])

    # display or save
    if not args.outfile:
        # display with some start/end padding
        print(f"{'*'*20} start csv {'*'*20}\n{csv_data}\n{'*'*21} end csv {'*'*21}")
    else:
        # save to designated file
        print(f'Saving to {args.outfile}')
        file = open(args.outfile, "w")
        file.write(csv_data)
        file.close()

    print(f'Done!')

def build_csv(headers, rows):
    """ 
    Return a formatted CSV, dynamically generated from headers/data

    :param headers: CSV header row (field names)
    :param rows: list of data to parse

    :return: string of csv data
    """
    # create csv output variable + add headers
    csv = f"{','.join(map(str, headers))}\n"

    for row in rows:
        row_data = [] # holds the data for each row before we add to csv

        # we only want to extract fields that match our headers
        for header in headers:
            if header in row:
                # some fields are lists of dicts
                if type(row[header]) == list:
                    # display a blank instead of '[]' for empty lists
                    if len(row[header]) == 0:
                        row_data.append('')
                    else:
                        subitems = []
                        if header == 'ipv4_addresses': # parse list, extract ip mask for each item within the field
                            for x in row[header]:
                                subitems.append(f"{x['ip']}/{x['cidr_netmask']}")
                        else: # parse list, extract q_origin_key for each item within the field
                            for x in row[header]:
                                subitems.append(x['q_origin_key'])
                        # join with a space, can't use comma due to csv
                        row_data.append(' '.join(map(str, subitems))) 
                else:
                    # this field is just a string/int, simply add it to the row
                    if type(row[header]) == str:
                        row_data.append(row[header].replace(",", ""))
                    else:
                        row_data.append(row[header])
            else:
                # display blanks where we have no info for this header
                row_data.append('')
        # append row to csv output
        csv += f"{','.join(map(str, row_data))}\n"

    return csv


def f_login(host,user,password,vdom):
    """ 
    Return a requests session after authenticating

    :param host: IP/FQDN of firewall
    :param user: FortiGate username
    :param password: FortiGate user password
    :param vdom: FortiGate VDOM

    :return: authenticated session or failure
    """
    # send the initial authentication request
    session = requests.session()
    p = session.post(f'https://{host}/logincheck',
        data=f'username={user}&secretkey={password}',
        verify=False,
        timeout=10)

    # extract CSRF token from cookies for use in headers
    for cookie in session.cookies:
        if cookie.name == 'ccsrftoken':
            print('Received CSRF token')
            session.headers.update({'X-CSRFTOKEN': cookie.value[1:-1]})

    # if there is a login banner, we need to 'accept' it
    if 'logindisclaimer' in p.text:
        print('Accepting login banner')
        session.post(f'https://{host}/logindisclaimer',
            data=f'confirm=1&redir=/ng',
            verify=False,
            timeout=10)

    # check login was successful
    try:
        login = session.get(f'https://{host}/api/v2/cmdb/system/vdom')
        login.raise_for_status()
        print(f'Successfully logged in as {user}')
    except Exception as e: 
        print(f'Failed to login with provided credentials: {e}')
        sys.exit(1)

    return session

if __name__ == "__main__":
    main()
