import subprocess
from subprocess import PIPE


def get_ip_adapters():
    """returns a list of available network adapters (currently limited to UNIX-based systems)"""

    # we get the return value for the shell command 'ifconfig -s' in byte-form
    return_value = subprocess.check_output(['ifconfig', '-s'])

    # decode return_value to a string and split it per line
    lines = return_value.decode('UTF-8').split('\n')
    adapters = []

    # for each line apart from the first one, if the line's length is larger than 1, store the first word
    for line in lines[1:]:
        if len(line) > 0:
            adapters.append(line.split()[0])

    return adapters


def enable_monitoring(adapter_name):
    """enable monitoring mode of the network card that is identified by string 'adapter_name'"""

    password = input("Please enter your password:")
    process = subprocess.Popen(['sudo', 'airmon-ng', 'start', adapter_name], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    process.communicate(input=password.encode())


def disable_monitoring(adapter_name):
    """disable monitoring mode of the network card that is identified by string 'adapter_name'"""

    password = input("Please enter your password:")
    process = subprocess.Popen(['sudo', 'airmon-ng', 'stop', adapter_name], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    process.communicate(input=password.encode())


def start_monitoring(adapter_name):
    """start monitoring for WiFi probe requests via probemon.py"""

    password = input("Please enter your password:")
    process = subprocess.Popen(['sudo', 'python', 'probemon.py', '-i', adapter_name, '-f', '-s', 'r', 'l'],
                               stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)

    process.communicate(input=password.encode())

    while process.poll() is None:
        line = process.stdout.readline()
        print(line)

    # print(process.stdout.read())


disable_monitoring("wlp3s0mon")
# start_monitoring("wlp3s0mon")
