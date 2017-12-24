"""
#Author: Renato Vieira


"""

import shlex
from subprocess import Popen, PIPE
import subprocess
import os


def runModule(hostname):
    strCmd = "openssl.exe";
    strArgs = "s_client -connect " + hostname + ":443 -cipher EXPORT";
    strFullCmd = "\"" + os.path.dirname(os.path.abspath("__file__")) + "\\OpenSSL\\" + strCmd + "\"" + " " + strArgs;

    args = shlex.split(strFullCmd)
    # print("Running Command.......");
    # proc = Popen(args, stdout=PIPE, stderr=PIPE,shell=True);
    # output = str(subprocess.check_output(strFullCmd));
    ps = subprocess.Popen(strFullCmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
    output = ps.communicate()[0];
    # output, err = proc.communicate();
    print(output);
    return output;


import sys
import time


def FreakFilter(output, host):
    if 'The system cannot find the path specified' in str(output):
        print("OpenSSL Binaries were not found. Exiting...");
        return;
    if 'gethostbyname failure' in str(output):
        print(host + " cannot be reached. Exiting...");
        return;
    if not ('CONNECTED') in str(output):
        print("Could Not connect to host:" + host);
        return;
    print("Running...");
    time.sleep(1);
    print("* Cipher tested");
    time.sleep(2);
    print("* Export cipher tested");
    time.sleep(2);
    print("Scan completed !");
    if ("Cipher is (NONE)" in str(output)):
        print("Your host (" + host + ") is Safe");
    else:
        print("Your host (" + host + ") is Vulnerable");


def main(url):


    host = url
    #FreakFilter(runModule(sys.argv[1]), sys.argv[1]);
    print(host)

    FreakFilter(runModule(host),host)

    print(host)

if __name__ == '__main__':
    main()