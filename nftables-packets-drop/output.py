import json
import os
from time import sleep
 
i = 0

while i < 10:
    if os.path.exists('output.json') == True:
        with open('output.json') as f:
        
            arp_t = 'ARP'
            icmp_t = 'ICMP'
            tcp_t = 'TCP'
            udp_t = 'UDP'
            ip_t = 'IP'
            ip6_t = 'IP6'
            ethernet_t = 'ETHERNET'
            dropped_t = 'DROPPED'
            json_data = json.load(f)['nftables']
            
            ba_arp_q = json_data[2]['counter']['packets']
            ba_arp_b = json_data[2]['counter']['bytes']
            bc_arp_q = json_data[10]['counter']['packets']
            bc_arp_b = json_data[10]['counter']['bytes']

            ba_icmp_q = json_data[3]['counter']['packets']
            ba_icmp_b = json_data[3]['counter']['bytes']
            bc_icmp_q = json_data[11]['counter']['packets']
            bc_icmp_b = json_data[11]['counter']['bytes']

            ba_tcp_q = json_data[4]['counter']['packets']
            ba_tcp_b = json_data[4]['counter']['bytes']
            bc_tcp_q = json_data[12]['counter']['packets']
            bc_tcp_b = json_data[12]['counter']['bytes']

            ba_udp_q = json_data[5]['counter']['packets']
            ba_udp_b = json_data[5]['counter']['bytes']
            bc_udp_q = json_data[13]['counter']['packets']
            bc_udp_b = json_data[13]['counter']['bytes']

            ba_ip_q = json_data[6]['counter']['packets']
            ba_ip_b = json_data[6]['counter']['bytes']
            bc_ip_q = json_data[14]['counter']['packets']
            bc_ip_b = json_data[14]['counter']['bytes']

            ba_ip6_q = json_data[7]['counter']['packets']
            ba_ip6_b = json_data[7]['counter']['bytes']
            bc_ip6_q = json_data[15]['counter']['packets']
            bc_ip6_b = json_data[15]['counter']['bytes']

            ba_ethernet_q = json_data[8]['counter']['packets']
            ba_ethernet_b = json_data[8]['counter']['bytes']
            bc_ethernet_q = json_data[16]['counter']['packets']
            bc_ethernet_b = json_data[16]['counter']['bytes']

            ba_dropped_q = json_data[9]['counter']['packets']
            ba_dropped_b = json_data[9]['counter']['bytes']
            bc_dropped_q = json_data[17]['counter']['packets']
            bc_dropped_b = json_data[17]['counter']['bytes']


            print ("{:<10} | {:<21} | {:<21} |".format('Ingress', 'BA_ETH', 'BC_ETH'))
            print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('', 'packets', 'Bytes', 'packets', 'Bytes'))
            print(f'{arp_t:<10} | {ba_arp_q:<10} {ba_arp_b:<10} | {bc_arp_q:<10} {bc_arp_b:<10} |')
            print (f'{icmp_t:<10} | {ba_icmp_q:<10} {ba_icmp_b:<10} | {bc_icmp_q:<10} {bc_icmp_b:<10} |')
            print (f'{tcp_t:<10} | {ba_tcp_q:<10} {ba_tcp_b:<10} | {bc_tcp_q:<10} {bc_tcp_b:<10} |')
            print (f'{udp_t:<10} | {ba_udp_q:<10} {ba_udp_b:<10} | {bc_udp_q:<10} {bc_udp_b:<10} |')
            print (f'{ip_t:<10} | {ba_ip_q:<10} {ba_ip_b:<10} | {bc_ip_q:<10} {bc_ip_b:<10} |')
            print (f'{ip6_t:<10} | {ba_ip6_q:<10} {ba_ip6_b:<10} | {bc_ip6_q:<10} {bc_ip6_b:<10} |')
            print (f'{ethernet_t:<10} | {ba_ethernet_q:<10} {ba_ethernet_b:<10} | {bc_ethernet_q:<10} {bc_ethernet_b:<10} |')
            print (f'{dropped_t:<10} | {ba_dropped_q:<10} {ba_dropped_b:<10} | {bc_dropped_q:<10} {bc_dropped_b:<10} |')

        break

    sleep(10)
    i+=1

