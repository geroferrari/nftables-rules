from time import sleep
from nftables import Nftables
import typer
import json
from sh import iperf3, ping, ErrorReturnCode
import netns
import sys
from loguru import logger
from datetime import datetime
from pathlib import Path
from itertools import product
from functools import partial


app = typer.Typer()

@app.command()
def print_table(json_file):
    with open(json_file, 'r') as f:
        json_data = json.load(f)

    for result in json_data:
        ##########################################################################
        ######################### Print Intial conditions ########################
        ##########################################################################

        print("Values for the test:")
        print(json.dumps(result[0], indent=4, sort_keys=True))
        print("")

        ##########################################################################
        ######################### Print nftables info ############################
        ##########################################################################

        nftables = result[1]['nftables']
        arp_t = 'ARP'
        icmp_t = 'ICMP'
        tcp_t = 'TCP'
        udp_t = 'UDP'
        ip_t = 'IP'
        ip6_t = 'IP6'
        ethernet_t = 'ETHERNET'
        dropped_dr_t = 'DROPPED DR'
        dropped_lr_t = 'DROPPED LR'
        
        ba_arp_q = nftables[2]['counter']['packets']
        ba_arp_b = nftables[2]['counter']['bytes']
        bc_arp_q = nftables[11]['counter']['packets']
        bc_arp_b = nftables[11]['counter']['bytes']

        ba_icmp_q = nftables[3]['counter']['packets']
        ba_icmp_b = nftables[3]['counter']['bytes']
        bc_icmp_q = nftables[12]['counter']['packets']
        bc_icmp_b = nftables[12]['counter']['bytes']

        ba_tcp_q = nftables[4]['counter']['packets']
        ba_tcp_b = nftables[4]['counter']['bytes']
        bc_tcp_q = nftables[13]['counter']['packets']
        bc_tcp_b = nftables[13]['counter']['bytes']

        ba_udp_q = nftables[5]['counter']['packets']
        ba_udp_b = nftables[5]['counter']['bytes']
        bc_udp_q = nftables[14]['counter']['packets']
        bc_udp_b = nftables[14]['counter']['bytes']

        ba_ip_q = nftables[6]['counter']['packets']
        ba_ip_b = nftables[6]['counter']['bytes']
        bc_ip_q = nftables[15]['counter']['packets']
        bc_ip_b = nftables[15]['counter']['bytes']

        ba_ip6_q = nftables[7]['counter']['packets']
        ba_ip6_b = nftables[7]['counter']['bytes']
        bc_ip6_q = nftables[16]['counter']['packets']
        bc_ip6_b = nftables[16]['counter']['bytes']

        ba_ethernet_q = nftables[8]['counter']['packets']
        ba_ethernet_b = nftables[8]['counter']['bytes']
        bc_ethernet_q = nftables[17]['counter']['packets']
        bc_ethernet_b = nftables[17]['counter']['bytes']

        ba_dropped_dr_q = nftables[9]['counter']['packets']
        ba_dropped_dr_b = nftables[9]['counter']['bytes']
        bc_dropped_dr_q = nftables[18]['counter']['packets']
        bc_dropped_dr_b = nftables[18]['counter']['bytes']

        ba_dropped_lr_q = nftables[10]['counter']['packets']
        ba_dropped_lr_b = nftables[10]['counter']['bytes']
        bc_dropped_lr_q = nftables[19]['counter']['packets']
        bc_dropped_lr_b = nftables[19]['counter']['bytes']

        print_nftable = ":------------- NFTABLES NS_B BA_ETH INGRESS -------------------: \n"
        print_nftable += "{:<10} | {:<21} | {:<21} |\n".format('Ingress', 'BA_ETH', 'BC_ETH')
        print_nftable += "{:<10} | {:<10} {:<10} | {:<10} {:<10} |\n".format('', 'packets', 'Bytes', 'packets', 'Bytes')
        print_nftable += (f"{arp_t:<10} | {ba_arp_q:<10} {ba_arp_b:<10} | {bc_arp_q:<10} {bc_arp_b:<10} | \n"
        f"{icmp_t:<10} | {ba_icmp_q:<10} {ba_icmp_b:<10} | {bc_icmp_q:<10} {bc_icmp_b:<10} |\n"
        f"{tcp_t:<10} | {ba_tcp_q:<10} {ba_tcp_b:<10} | {bc_tcp_q:<10} {bc_tcp_b:<10} |\n"
        f"{udp_t:<10} | {ba_udp_q:<10} {ba_udp_b:<10} | {bc_udp_q:<10} {bc_udp_b:<10} |\n"
        f"{ip_t:<10} | {ba_ip_q:<10} {ba_ip_b:<10} | {bc_ip_q:<10} {bc_ip_b:<10} |\n"
        f"{ip6_t:<10} | {ba_ip6_q:<10} {ba_ip6_b:<10} | {bc_ip6_q:<10} {bc_ip6_b:<10} |\n"
        f"{ethernet_t:<10} | {ba_ethernet_q:<10} {ba_ethernet_b:<10} | {bc_ethernet_q:<10} {bc_ethernet_b:<10} |\n"
        f"{dropped_dr_t:<10} | {ba_dropped_dr_q:<10} {ba_dropped_dr_b:<10} | {bc_dropped_dr_q:<10} {bc_dropped_dr_b:<10} |\n"
        f"{dropped_lr_t:<10} | {ba_dropped_lr_q:<10} {ba_dropped_lr_b:<10} | {bc_dropped_lr_q:<10} {bc_dropped_lr_b:<10} |\n")
        print_nftable += ":-------------------------------------------------------------: \n"
        print_nftable += "\n"

        print(print_nftable)

        ##########################################################################
        ######################### Print iperf info ###############################
        ##########################################################################

        print("Iperf3 values:")
        print(json.dumps(result[1]["end"]["sum"], indent=4, sort_keys=True))
        print("")

        print("Cpu utilization percentage:")
        print(json.dumps(result[1]["end"]["cpu_utilization_percent"], indent=4, sort_keys=True))

        bps = result[1]['end']['sum']['bits_per_second']
        lost_percent = result[1]['end']['sum']['lost_percent']
        time_delay = result[1]['end']['sum']['seconds'] - result[1]['end']['streams'][0]['udp']['seconds']
        print(f'bps: {bps/1e9:0.3f}')
        print(f'Lost Percent: {lost_percent:0.1f}%')
        print(f'Delay measured: {time_delay}s')

        print("_______________________________________________________________________")

if __name__ == '__main__':
    app()