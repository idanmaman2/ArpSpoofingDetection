import threading
import time
import logging
from scapy.all import ARP, Ether, sniff
import subprocess 
import re 

FORMAT = '%(asctime)s %(clientip)-15s %(user)-8s %(message)s'
logging.basicConfig(format=FORMAT,filename="log.out",filemode='w')
d = {'clientip': '192.168.0.1', 'user': 'fbloggs'}
logging.warning('Protocol problem: %s', 'connection reset', extra=d)



def checkArpTable():
    while(True):
        result = subprocess.check_output("arp -a ", shell=True).decode(encoding='ascii')
        rows = result.split("\n")
        rowparsed = list(filter ( bool , map( lambda x : re.findall(".* \((.*)\) at (.*) \[ether\] on (.*)",x) , rows))) 
        dicty = set(map( lambda x : x[0][1],rowparsed))
        print(rowparsed)
        print(len(dicty) == len(rowparsed))
        time.sleep(2)
        
def packetHandle(pack): 
    arpp = pack[ARP]
    
    
  
trcheck = threading.Thread(target=checkArpTable)
trcheck.start()
sniff( 
    lfilter = lambda x : ARP in x   
      ,
      prn = lambda packet : threading.Thread(target = packetHandle ,args = (packet , )).start()  )