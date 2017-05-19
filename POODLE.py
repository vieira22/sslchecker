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

import socket, ssl, pprint, sys, IPy, argparse, multiprocessing


def print_results(host, port, sslv3, tlsv1):
    if tlsv1 is None:
        print("{0}:{1} SSLv3 {2}".format(str(host), port, sslv3))
        return

    if sslv3 == "enabled" and tlsv1 != "enabled":
        print("{0}:{1} SSLv3 enabled and TLSv1 not enabled".format(str(host), port))
    else:
        print("{0}:{1} SSLv3={2} TLSv1={3}".format(str(host), port, sslv3, tlsv1))

def main(hostname):

    arr = {'host': [hostname], 'port': [443], 'network': None, 'tls': False, 'parallel': False}

    tlsv1 = None

    if arr["host"] is not None:
        for host in arr["host"]:
            for p in arr["port"]:
                sslv3 = check_sslv3(host, p)
                if arr["tls"] == True:
                    tlsv1 = 'null'
                print_results(host, p, sslv3, tlsv1)
        return

    net = IPy.IPSet()

    for network in arr["network"]:
        net.add(IPy.IP(network))

    if arr["parallel"]:
        p = multiprocessing.Pool()
        q = multiprocessing.Queue()

        for ip in net:
            q.put((check_net, ip, arr["port"], arr["tls"]))

        while True:
            items = q.get()
            func = items[0]
            args = items[1:]
            p.apply_async(func, args)
            if q.empty():
                p.close()
                p.join()
                break
    else:
        for ip in net:
            check_net(ip, arr["port"], arr["tls"])

def check_net(ip, ports, tls):
    for x in ip:
        if ip.prefixlen() != 32 and (ip.broadcast() == x or ip.net() == x):
            continue
        for p in ports:
            tlsv1 = 'null'
            sslv3 = check_sslv3(x, p)
            print_results(x, p, sslv3, tlsv1)



def check_sslv3(h, p):
    return check(h, p, ssl.PROTOCOL_SSLv3)

def check(h, p, ctx):
    context = ssl.SSLContext(ctx)
    context.verify_mode = ssl.CERT_NONE

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        ssl_sock = context.wrap_socket(s, server_hostname=str(h), do_handshake_on_connect=True)
        ssl_sock.connect((str(h), int(p)))
        ssl_sock.close()
        return "enabled - INSECURE"
    except Exception as e:
        return str("not Enabled - SECURE")

if __name__ == "__main__":
        main()