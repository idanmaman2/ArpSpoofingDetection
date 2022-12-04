from scapy.all import Ether , ARP,conf, get_if_addr , get_if_hwaddr,srp1,sendp
BROADCASTMAC = "ff:ff:ff:ff:ff:ff"

def getTargetMac(target : str , interface : str )->str : #get mac from ip  
    etherAttack = Ether(dst =BROADCASTMAC)
    arpAttack = ARP(pdst = target  , op = "who-has" )
    reply = srp1(etherAttack/arpAttack , iface = interface,verbose=False)
    return reply[Ether].src