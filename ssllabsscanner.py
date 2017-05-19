"""
#Author: Renato Vieira, Adley Silva, Claudio Carvalho 

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE  See the
# GNU General Public License for more details. http://www.gnu.org/licenses/.

Requirements:
Python 3.4.0 - Python.org
TLSFuzzer - https://github.com/tomato42/tlsfuzzer
tlslite-ng - https://github.com/tomato42/tlslite-ng
ECDSA - https://github.com/warner/python-ecdsa


More information at:
https://sslvulnerabilitychecker.com
https://github.com/vieira22/SSLChecker
"""


import requests
import time
import sys
import logging

API = 'https://api.ssllabs.com/api/v2/'

def requestAPI(path, payload={}):
    '''This is a helper method that takes the path to the relevant
        API call and the user-defined payload and requests the
        data/server test from Qualys SSL Labs.

        Returns JSON formatted data'''

    url = API + path

    try:
        response = requests.get(url, params=payload)
    except requests.exception.RequestException:
        logging.exception('Request failed.')
        sys.exit(1)

    data = response.json()
    return data


def resultsFromCache(host, publish='off', startNew='off', fromCache='on', all='on'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'fromCache': fromCache,
                'all': all
              }
    data = requestAPI(path, payload)
    return data


def newScan(host, publish='off', startNew='on', all='done', ignoreMismatch='off'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'all': all,
                'ignoreMismatch': ignoreMismatch
              }
    results = requestAPI(path, payload)

    payload.pop('startNew')

    while results['status'] != 'READY' and results['status'] != 'ERROR':
        time.sleep(300)
        results = requestAPI(path, payload)

    return results
