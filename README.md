# TLS / SSL Vulnerability Checker
TLS / SSL Vulnerability Checker

TLS /SSL Vulnerability Checker is a project developed as Python scripts to return vulnerabilities on the attacks below:

#### POODLE  ####

A POODLE attack is an exploit that takes advantage of the way some browsers deal with encryption. POODLE (Padding Oracle On Downgraded Legacy Encryption) is the name of the vulnerability that enables the exploit.


#### DROWN ####

DROWN is a serious vulnerability that affects HTTPS and other services that rely on SSL and TLS, some of the essential cryptographic protocols for Internet security. These protocols allow everyone on the Internet to browse the web, use email, shop online, and send instant messages without third-parties being able to read the communication. DROWN allows attackers to break the encryption and read or steal sensitive communications, including passwords, credit card numbers, trade secrets, or financial data. Our measurements indicate 33% of all HTTPS servers are vulnerable to the attack.


#### Heartbleed ####

Heartbleed is a vulnerability in the OpenSSL library through the heartbeat extensions of the TLS / DTLS protocols. The attack consists of opening an SSL connection on a server, and request through the Heartbeat packets (small packets that kill an active TCP connection) more bits than your connection is transferring (Limited to 64 bits per transmission). When you make a request of this type the server responds to your heartbeat with your information and with the next bits that are in the server's RAM (which are data from other open connections from the same server).


#### FREAK ####

FREAK (Factoring RSA Export Keys) is a vulnerability in several implementations of SSL that was discovered at the end of 2014/beginning of 2015.
It consist on the 6 steps below following the structure on the design. A client wants to open an SSL connection with a server. Little do they know that there is a Man lurking In The Middle.



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

Screnshot 1 - 

![alt text](https://raw.githubusercontent.com/vieira22/sslchecker/master/Screenshots/pythonshot1.JPG)

Screenshot 2 -

![alt text](https://raw.githubusercontent.com/vieira22/sslchecker/master/Screenshots/pythonshot2.JPG)

Screenshot 3 - 

![alt text](https://raw.githubusercontent.com/vieira22/sslchecker/master/Screenshots/pythonshot3.JPG)

