#!/usr/bin/env python
import scapy.all as scapy
import argparse


def get_ip():

    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target", dest="ipadrr", help="Enter spesefic ip address of your target")
    options = parser.parse_args()

    if not options.ipadrr:
        parser.error ("IP address that you entered was wrong try again!")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(result_list):
    print("IP\t\t\tMAC\n-----------------------------------------------------------")
    for client in result_list:
        print client['ip'],"\t\t",client['mac']

ip = get_ip()

scan_result = scan(ip.ipadrr)

print_result(scan_result)
