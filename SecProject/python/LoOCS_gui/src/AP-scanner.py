from collections import namedtuple, Set
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
from scapy.layers.eap import EAPOL
from scapy.all import *
from threading import Thread
import time
import os


networks = {}
clients = {}
Network = namedtuple("Network", "BSSID SSID Signal_dBm Channel Crypto Clients")


def pkt_received(pkt):
    # frame with type 0 (management frame) and subtype 8 (beacon frame)
    if pkt.getlayer(Dot11).type == 0 and pkt.getlayer(Dot11).subtype == 8:

        # get the bssid (mac address) of the access point
        bssid = pkt[Dot11].addr2

        # get the SSID of the access point
        ssid = pkt[Dot11Elt].info.decode()

        # attempt to retrieve the signal strength for the AP
        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        try:
            # extract network stats
            stats = pkt[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            # get the crypto
            crypto = stats.get("crypto")
        except:
            channel = "N/A"
            crypto = "N/A"

        # if the access point has a client list declared
        if bssid in clients:
            networks[bssid] = (Network(bssid, ssid, dbm_signal, channel, crypto, clients[bssid]))
        else:
            networks[bssid] = (Network(bssid, ssid, dbm_signal, channel, crypto, set()))

    # frame with type 2 (data frame) that is not an EAPOL frame: this way we make sure the AP and client actually
    # have an ongoing connection
    elif pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
        src = pkt.getlayer(Dot11).addr2
        dest = pkt.getlayer(Dot11).addr1

        # if the source mac address is known as an AP to us
        if src in networks:
            # initialize the client list if the key was not known
            if src not in clients:
                clients[src] = set()
            # ignore broadcast channel
            if dest != "ff:ff:ff:ff:ff:ff":
                clients[src].add(dest)

        # if the destination mac address is known as an AP to us
        if dest in networks:
            # initialize the client list if the key was not known
            if dest not in clients:
                clients[dest] = set()
            # ignore broadcast channel
            if src != "ff:ff:ff:ff:ff:ff":
                clients[dest].add(src)


def print_all():
    while True:
        os.system("clear")
        for key, value in networks.items():
            print(key, ' : ', value)
        time.sleep(0.5)


def change_channel():
    ch = 1
    interface = "wlp3s0mon"
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlp3s0mon"
    # # start the thread that prints all the networks
    # printer = Thread(target=print_all)
    # printer.daemon = True
    # printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=pkt_received, iface=interface)
