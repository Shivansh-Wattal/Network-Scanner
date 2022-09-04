import optparse
import scapy.all as scapy


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="IP range to search.")
    (options,arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify an ip or ip range , use --help for more info.")
    return options.ip

def scan(IP):
    arp_request = scapy.ARP(pdst=IP)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broacast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broacast, timeout=1, verbose=False)[0]

    devices_list=[]
    for element in answered_list:
        device_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device_dict)
    return devices_list

def print_scan_result(result_list):
    print("IP\t\t\tMAC Address\n----------------------------------")
    for device in result_list:
        print(device["ip"] + "\t\t" + device["mac"])

ip_range=get_arguments()
scan_result = scan (ip_range)
print_scan_result(scan_result)
