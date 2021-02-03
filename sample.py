#!/usr/bin/env python
from __future__ import print_function
import sys
import requests
from datetime import datetime, timedelta

API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'


def get_data(query):

    full_query = API_HOST + query
    r = requests.get(full_query)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
              'query:\n{}'.format(r.status_code, full_query))
        sys.exit(1)

    if not r.json():
        print('No data returned with the following query:')
        print(full_query)
        sys.exit(0)

    return r.json()


# Get a get CVE
endpoint = '/cve/CVE-2019-1125'
params = 'advisory=RHSA-2016:1847'

data = get_data(endpoint + '?' + params)


# find the RHSA for a specific CVE - In this case we only will care about 7.6 EUS
for affected_release in data['affected_release']:
    print(affected_release['product_name'] + " " + affected_release['advisory'])
    #, affected_release['advisory']

# For that RHSA, get the fixed package names with proper revision
