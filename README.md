# SSL Vulnerability Checker
SSL Vulnerability Checker

SSL Vulnerability Checker is a project developed as Python scripts to return vulnerabilities on the 3 attacks:

#### POODLE  ####

A POODLE attack is an exploit that takes advantage of the way some browsers deal with encryption. POODLE (Padding Oracle On Downgraded Legacy Encryption) is the name of the vulnerability that enables the exploit.


#### DROWN ####

A POODLE attack is an exploit that takes advantage of the way some browsers deal with encryption. POODLE (Padding Oracle On Downgraded Legacy Encryption) is the name of the vulnerability that enables the exploit.


#### Heartbleed ####

DROWN is a serious vulnerability that affects HTTPS and other services that rely on SSL and TLS, some of the essential cryptographic protocols for Internet security. These protocols allow everyone on the Internet to browse the web, use email, shop online, and send instant messages without third-parties being able to read the communication. DROWN allows attackers to break the encryption and read or steal sensitive communications, including passwords, credit card numbers, trade secrets, or financial data. Our measurements indicate 33% of all HTTPS servers are vulnerable to the attack.


#### Requirements:
Python 3.4.0 - Python.org

TLSFuzzer - https://github.com/tomato42/tlsfuzzer

tlslite-ng - https://github.com/tomato42/tlslite-ng

ECDSA - https://github.com/warner/python-ecdsa

For Windows - PyCharm or another IDE

For more about SSL Checker please visit:
https://sslvulnerabilitychecker.com



#### Instructions on Use:

Usage: <script-name> [-h hostname]
-h hostname   hostname to connect to, \"sslvulnerabilitychecker.com\" by default
--help        this message

E.g.: c:\>Python sslchecker.py -h sslvulnerabilitychecker.com


#### Results:




