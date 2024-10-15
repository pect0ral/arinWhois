#!/usr/bin/env python3
import requests
import json
import sys
import argparse
import re
import pprint

def arin_whois_query(entity_type, query_value):
    base_url = 'https://whois.arin.net/rest'
    url = f"{base_url}/{entity_type}/{query_value}.json"

    response = requests.get(url)

    if response.status_code == 200:
        json_data = json.loads(response.text)
        return json_data
    else:
        print(f"Error: {response.status_code}")
        return None


def extract_value(data, *keys):
    for key in keys:
        data = data.get(key, {})
    return data.get("$", "") if isinstance(data, dict) else ""


def transform_data(data):
    net_data = data.get("net", {})
    org_ref_data = net_data.get("orgRef", {})
    parent_net_ref_data = net_data.get("parentNetRef", {})
    net_blocks_data = net_data.get("netBlocks", {})
    net_blocks = net_blocks_data.get("netBlock", [])

    if isinstance(net_blocks, dict):
        net_blocks = [net_blocks]

    transformed_net_blocks = [
        {
            "cidrLength": extract_value(net_block, "cidrLength"),
            "endAddress": extract_value(net_block, "endAddress"),
            "description": extract_value(net_block, "description"),
            "type": extract_value(net_block, "type"),
            "startAddress": extract_value(net_block, "startAddress"),
        }
        for net_block in net_blocks
    ]

    transformed_data = {

            "registrationDate": extract_value(net_data, "registrationDate"),
            "rdapRef": extract_value(net_data, "rdapRef"),
            "ref": extract_value(net_data, "ref"),
            "endAddress": extract_value(net_data, "endAddress"),
            "handle": extract_value(net_data, "handle"),
            "name": extract_value(net_data, "name"),
            "netBlocks": {"netBlock": transformed_net_blocks},
            "orgRef": {
                "handle": org_ref_data.get("@handle", ""),
                "name": org_ref_data.get("@name", ""),
                "orgLink": extract_value(org_ref_data),
            },
            "parentNetRef": {
                "handle": parent_net_ref_data.get("@handle", ""),
                "name": parent_net_ref_data.get("@name", ""),
                "parentNetLink": extract_value(parent_net_ref_data),
            },
            "startAddress": extract_value(net_data, "startAddress"),
            "updateDate": extract_value(net_data, "updateDate"),
            "version": extract_value(net_data, "version"),
        }

    return transformed_data


def transform_org_data(data):
    org_data = data['org']
    transformed_org = {
        'name': org_data.get('name', {}).get('$'),
        'handle': org_data.get('handle', {}).get('$'),
        'registrationDate': org_data.get('registrationDate', {}).get('$'),
        'updateDate': org_data.get('updateDate', {}).get('$'),
        'canAllocate': org_data.get('canAllocate', {}).get('$'),
        'city': org_data.get('city', {}).get('$'),
        'postalCode': org_data.get('postalCode', {}).get('$'),
        'iso3166-1': org_data.get('iso3166-1', {}).get('name', {}).get('$'),
        'iso3166-2': org_data.get('iso3166-2', {}).get('$'),
        # 'streetAddress': org_data.get('streetAddress', {}).get('line', {}).get('$')
        # We don't need no stinkin street address
    }

    return transformed_org


def main():
    parser = argparse.ArgumentParser(description="Query ARIN Whois API.")
    parser.add_argument("-o", "--org", help="Search organization", metavar="ORG")
    parser.add_argument("-i", "--ip", help="Search IP address", metavar="IP")
    parser.add_argument("-n", "--net", help="Search network", metavar="NET")
    parser.add_argument("-c", "--customer", help="Search customer", metavar="CUSTOMER")
    parser.add_argument("-e", "--entity", help="Search other entity types", metavar="ENTITY")

    args = parser.parse_args()

    if args.org:
        result = arin_whois_query('org', args.org)
        transformed_result = transform_org_data(result)
        print(json.dumps(transformed_result, indent=2))

    elif args.ip:
        result = arin_whois_query('ip', args.ip)
        transformed_result = transform_data(result)
        print(json.dumps(transformed_result, indent=2))


    elif args.net:
        result = arin_whois_query('net', args.net)
        transformed_result = transform_data(result)
        print(json.dumps(transformed_result, indent=2))

    elif args.customer:
        result = arin_whois_query('customer', args.customer)
    elif args.entity:
        result = arin_whois_query(args.entity.split(":")[0], args.entity.split(":")[1])
    else:
        print("No arguments provided. Use -h or --help for help.")
        sys.exit(1)

    if result and not args.ip and not args.net and not args.org:
        pprint.pprint(result)
if __name__ == "__main__":
    main()


