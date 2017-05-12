"""
Check a domain, if contains SSL certificate and return vulnerabilities (Heartbleed, POODLE and DROWN Scan).
There is more details on the file attached. 
I found the DROWN and POODLE Script already (attached), 
so you would need to find the heartbleed and make a single script from it.
If you know the application whois, 
we want something close to that but returning the information described on the attached file.

Please let me know if you need any further information.

Poodle Scanner = https://github.com/0xICF/POODLEScanner/blob/master/POODLEScanner.py

Drown = http://www.thegeekstuff.com/2016/03/drown-attack-test-and-fix/

SSL grade = https://github.com/TrullJ/ssllabs
"""

import ssl
import socket
import HeartbleedTest
import POODLEScanner
import ssllabsscanner


def get_ssl_details(url, port=443):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
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
    data = ssllabsscanner.resultsFromCache(hostname)
    try:
        if 'grade' in data['endpoints'][0]:
            print('SSL grade: {}'.format(data['endpoints'][0]['grade']))
        else:
            print('SSL grade error: {}'.format(data['endpoints'][0]['statusMessage']))
    except Exception:
        print('SSL grade not available')


hostname = 'google.com'

print('Testing host {}'.format(hostname))
print('#########################################')
print('SSL details')
print('#########################################')

# print_dict(get_ssl_details(hostname))  # Prints all SSL details as raw data
get_ssl_details(hostname)

get_ssl_grade(hostname)
print('')
print('#########################################')
print('Heartbleed test')
print('#########################################')
HeartbleedTest.main(hostname)
print('')
print('#########################################')
print('POODLE test:')
print('#########################################')
POODLEScanner.main(hostname)
