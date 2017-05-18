"""
#Author: Renato Vieira

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


import ssl
import socket
import Heartbleed
import POODLE
import ssllabsscanner
import DROWN
import sys
import getopt

def get_ssl_details(url, port=443):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=url)
    try:
        s.connect((url, 443))
        cert = s.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject['commonName']
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer['commonName']

        print('Certificate details:')
        print('Certificate Owner: {}'.format(issued_to))
        print('Certificate Issuer: {}'.format(issued_by))
        print('Issued Date: {}'.format(cert['notBefore']))
        print('Expiring Date: {}'.format(cert['notAfter']))
        print('Serial Number: {}'.format(cert['serialNumber']))
        print('Version: {}'.format(cert['version']))

        return cert
    except Exception as e:
        print(e)


def print_dict(d, indent=0):
   for key, value in d.items():
      print ('\t' * indent + str(key))
      if isinstance(value, dict):
         print_dict(value, indent+1)
      else:
         print ('\t' * (indent+1) + str(value))


def get_ssl_grade(hostname):
    print('#########################################')

    data = ssllabsscanner.resultsFromCache(hostname)
    try:
        if 'grade' in data['endpoints'][0]:
            print('SSL rating: {}'.format(data['endpoints'][0]['grade']))
        else:
            print('SSL rating error: {}'.format(data['endpoints'][0]['statusMessage']))
    except Exception:
        print('SSL rating not available')


def help_msg():
    """Print usage information"""
    print("Usage: <script-name> [-h hostname]")
    print(" -h hostname   hostname to connect to, \"sslvulnerabilitychecker.com\" by default")
    print(" --help        this message")

def main():
    """Test if the server supports some of the SSLv2 ciphers"""
    conversations = {}
    host = "sslvulnerabilitychecker.com"
    port = 4433

    argv = sys.argv[1:]

    opts, argv = getopt.getopt(argv, "h:p:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
            maincall(host)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))
    if argv:
        help_msg()
        raise ValueError("Unknown options: {0}".format(argv))
    maincall(host)

def maincall(host):
    hostname = host

    print('Testing host {}'.format(hostname))
    print('#########################################')
    print('SSL details')
    print('#########################################')



    # print_dict(get_ssl_details(hostname))  # Prints all SSL details as raw data
    get_ssl_details(hostname)

    get_ssl_grade(hostname)

    print('#########################################')
    print('')
    print('*********************************************************************')
    print('')
    print('Heartbleed test')
    print('#########################################')
    Heartbleed.main(hostname)
    print('')
    print('*********************************************************************')
    print('')
    print('POODLE test:')
    print('#########################################')
    POODLE.main(hostname)
    print('#########################################')
    print('')
    print('*********************************************************************')
    print('')
    print('DROWN test:')
    print('#########################################')
    DROWN.main(hostname)
    print('#########################################')
    print('')
    print('')
    print('')
    print("Thanks for using SSL Vulnerability Checker tool.")
    print('')
    print("For more details on Attacks visit sslvulnerabilitychecker.com .")
    print('')
    print("Find the SSL Checker project on github.com/vieirar22/sslchecker .")
    print("")
    print("Version 1.0 - 05/2017")
    print("")

    print("")

if __name__ == "__main__":
        main()