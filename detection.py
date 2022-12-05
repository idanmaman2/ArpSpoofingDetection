import threading
import time
import logging
from scapy.all import ARP, Ether, sniff, get_if_hwaddr, get_if_addr, conf
import subprocess 
import re 

import arpUtil

FORMAT = '%(asctime)s %(clientip)-15s %(user)-8s %(message)s'
logging.basicConfig(format=FORMAT,filename="log.out",filemode='w')
d = {'clientip': '192.168.0.1', 'user': 'fbloggs'}
logging.warning('Protocol problem: %s', 'connection reset', extra=d)

interface = conf.iface
myMac = get_if_hwaddr(interface)
myIp = get_if_addr(interface)

def checkArpTableForDuplicates():
    '''
    First check: check the arp table for duplicates - more than one entry
    with the same IP (if the attacker spoof you, you will have two entries
    with his IP. One with his real MAC address and one assosciated with
    the target MAC address)
    '''
    while(True):   
        result = subprocess.check_output("arp -a ", shell=True).decode(encoding='ascii')
        rows = result.split("\n")
        rowparsed = list(filter ( bool , map( lambda x : re.findall(".* \((.*)\) at (.*) \[ether\] on (.*)",x) , rows))) 
        dicty = set(map( lambda x : x[0][1],rowparsed))
        print(len(dicty),",",len(rowparsed))
        if len(dicty) != len(rowparsed):
            print("Check1 detected an attack!!!")
        time.sleep(2)


arpQueries = {}
def checkMessages():
    '''
    Second check: check that we don't get "is-at" messages without
    we sented an "who-has" message. If we detect one, we will verify
    its MAC address using "who-has" question.
    '''
    sniff( 
        lfilter = lambda x : ARP in x,
        prn = lambda packet : threading.Thread(target = packetHandle ,
                                            args = (packet , )).start() 
        )

def packetHandle(pack): 
        arpp = pack[ARP]
        # arpp is a "who-has" message -> add query
        if arpp.op == 1 and arpp.hwsrc == myMac and arpp.psrc == myIp:
            addQuery(arpp)
        # arpp is a "is-at" message -> remove query
        elif arpp.op == 2:
            if(isQuestionExist(arpp)):
                print(arpQueries)
                removeQuery(arpp)
                print(arpQueries)
            else:
                print("check2 detected an attack!!! attacker MAC address:", arpp.hwsrc, " spoofed Mac adresss:")


def addQuery(arpp):
    if(arpp.pdst in arpQueries):
        arpQueries[arpp.pdst] += 1
    else: arpQueries[arpp.pdst] = 1

def removeQuery(arpp):
    arpQueries[arpp.pdst] -= 1

def isQuestionExist(arpp):
    if arpp.pdst in arpQueries:
        if arpQueries[arpp.pdst] > 0:
            return True
        else: return False
    else: return False

def verifyAddress(ip, fishyMac):
    realMac = arpUtil.getTargetMac(ip, interface)
    return (realMac == fishyMac, realMac)

trcheck1 = threading.Thread(target=checkArpTableForDuplicates)
trcheck1.start()

trcheck2 = threading.Thread(target=checkMessages)
trcheck2.start()



