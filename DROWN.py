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

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientMasterKeyGenerator
from tlsfuzzer.expect import ExpectAlert, ExpectClose, ExpectServerHello2, \
        ExpectSSL2Alert

from tlslite.constants import CipherSuite, AlertLevel, \
        ExtensionType, SSL2ErrorDescription

def main(host):
    """Test if the server supports some of the SSLv2 ciphers"""
    conversations = {}
    host = host
    port = 443

    for prot_vers, proto_name in {
            (0, 2):"SSLv2",
            (3, 0):"SSLv3",
            (3, 1):"TLSv1.0"
            }.items():
        for cipher_id, cipher_name in {
                CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5:"DES-CBC3-MD5",
                CipherSuite.SSL_CK_RC2_128_CBC_WITH_MD5: "RC2-CBC-MD5",
                CipherSuite.SSL_CK_RC4_128_WITH_MD5:"RC4-MD5",
                CipherSuite.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5:"EXP-RC2-CBC-MD5",
                CipherSuite.SSL_CK_IDEA_128_CBC_WITH_MD5:"IDEA-CBC-MD5",
                CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5: "EXP-RC4-MD5",
                CipherSuite.SSL_CK_DES_64_CBC_WITH_MD5:"DES-CBC-MD5"
                }.items():
            conversation = Connect(host, port, version=(0, 2))
            node = conversation
            ciphers = [CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
                       CipherSuite.SSL_CK_RC4_128_WITH_MD5,
                       CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5,
                       CipherSuite.SSL_CK_RC2_128_CBC_WITH_MD5,
                       CipherSuite.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
                       CipherSuite.SSL_CK_IDEA_128_CBC_WITH_MD5,
                       CipherSuite.SSL_CK_DES_64_CBC_WITH_MD5]

            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       version=prot_vers,
                                                       ssl2=True))
            # we can get a ServerHello with no ciphers:
            node = node.add_child(ExpectServerHello2())
            # or we can get an error stright away, and connection closure
            node.next_sibling = ExpectSSL2Alert(SSL2ErrorDescription.no_cipher)
            node.next_sibling.add_child(ExpectClose())
            alternative = node.next_sibling
            # or the server may close the connection right away (likely in
            # case SSLv2 is completely disabled)
            alternative.next_sibling = ExpectClose()
            alternative = alternative.next_sibling
            # or finally, we can get a TLS Alert message
            alternative.next_sibling = ExpectAlert()
            alternative.next_sibling.add_child(ExpectClose())
            # in case we got ServerHello, try to force one of the ciphers
            node = node.add_child(ClientMasterKeyGenerator(cipher=cipher_id))
            # it should result in error
            node = node.add_child(ExpectSSL2Alert())
            # or connection close
            node.next_sibling = ExpectClose()
            # in case of error, we expect the server to close connection
            node = node.add_child(ExpectClose())

            conversations["Connect with {1} {0}"
                          .format(cipher_name, proto_name)] = conversation

    good = 0
    bad = 0

    for conversation_name, conversation in conversations.items():
        print("{0} ...".format(conversation_name))

        runner = Runner(conversation)

        res = True
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            print("")
            res = False

        if res:
            good+=1
            print("OK\n")
        else:
            bad+=1


    print("End of the Test")
    print("Successful: {0}".format(good))
    print("Failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
