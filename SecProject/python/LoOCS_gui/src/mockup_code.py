# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/max/Documents/2IC80/mockup.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!
import time

from PyQt5 import QtCore, QtGui, QtWidgets

# from src.helper_functions import get_ip_adapters
import subprocess
from subprocess import PIPE


class Ui_MainWindow(object):
    def __init__(self):
        self.is_sniffing = False
        self.has_ap = False
        self.mon_adapter = ""
        self.ap_adapter = ""
        self.mon_label = QtWidgets.QLabel("")
        self.ap_label = QtWidgets.QLabel("")
        self.adapters = self.get_ip_adapters()
        self.ssid = "hackerman1233"

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
        self.layoutWidget_3 = QtWidgets.QWidget(self.splitter_2)
        self.layoutWidget_3.setObjectName("layoutWidget_3")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.layoutWidget_3)
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
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
        self.listWidget = QtWidgets.QListWidget(self.layoutWidget)
        self.listWidget.setObjectName("listWidget")
        self.verticalLayout.addWidget(self.listWidget)
        self.layoutWidget1 = QtWidgets.QWidget(self.splitter)
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.layoutWidget1)
        self.verticalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
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
        self.label_7.setText(_translate("MainWindow", "AP\'s in vicinity"))
        self.label.setText(_translate("MainWindow", "SSID\'s to mimic"))
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

    def start_sniffing(self):
        self.mon_adapter = self.mon_box.currentText()
        self.enable_monitoring(self.mon_adapter)
        self.is_sniffing = True

        self.mon_label.setText("Monitoring...")
        self.mon_action.setStatusTip("Stop monitoring")
        self.mon_box.setEnabled(False)

        self.mon_action.triggered.connect(self.stop_sniffing)

        self.retranslateUi(MainWindow)

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
                       "channel=[AP Channel]\n"
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
                       "listen-address=127.0.0.1".format(self.ap_adapter + "mon"))

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


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
