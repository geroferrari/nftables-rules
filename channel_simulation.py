#!venv/bin/python3
from time import sleep
from nftables import Nftables
import typer
import json
from sh import iperf3, ping, ErrorReturnCode
import netns
import sys
from loguru import logger


app = typer.Typer()

IPERF3_SERVER = '172.17.100.2'

family = 'netdev'
table = 'example'
ns_ba_ingress = 'ns_ba_ingress'
fwd_chain_ac = 'fwd_chain_ac'
ns_bc_ingress = 'ns_bc_ingress'
fwd_chain_ca = 'fwd_chain_ca'
chain_type = 'filter'
hook = 'ingress'
dev_ba = 'ba_eth'
dev_bc = 'bc_eth'
priority = 1
policy = 'accept'

NFT_CONFIG = [
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_arp',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_icmp',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_tcp',
            }},            
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_udp',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_ip',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_ip6',
            }},                
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_ethernet',
            }},                
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_dropped_by_packetloss',
            }}, 
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_ba_ingress_dropped_by_limit',
            }},                
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_arp',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_icmp',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_tcp',
            }},            
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_udp',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_ip',
            }},
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_ip6',
            }},                
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_ethernet',
            }},                
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_dropped_by_packetloss',
            }}, 
            {'counter': { 
                'family': family,
                'table': table,
                'name': 'counter_ns_bc_ingress_dropped_by_limit',
            }},                  
            {'add': {'rule':
                     {
                         'family': family,
                         'table': table,
                         'chain': ns_ba_ingress,
                         "expr": [{
                             "match": {
                                 "op": "==",
                                 "left": {"payload": {"protocol": "ip", "field": "version"}},
                                 "right": 4
                             }},
                             {"counter": "counter_ns_ba_ingress_ip"}
                         ]}}
            },
            {'add': {'rule':
                     {
                         'family': family,
                         'table': table,
                         'chain': ns_ba_ingress,
                         "expr": [{
                             "match": {
                                 "op": "==",
                                 "left": {"payload": {"protocol": "arp", "field": "ptype"}},
                                 "right": "ip"
                             }},
                             {"counter": "counter_ns_ba_ingress_arp"}
                         ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_ba_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "protocol"}},
                                "right": "icmp"
                            }},
                            {"counter": "counter_ns_ba_ingress_icmp"}
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_ba_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "protocol"}},
                                "right": "tcp"
                            }},
                            {"counter": "counter_ns_ba_ingress_tcp"}
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_ba_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "protocol"}},
                                "right": "udp"
                            }},
                            {"counter": "counter_ns_ba_ingress_udp"}
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_ba_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip6", "field": "nexthdr"}},
                                "right": "ipv6-icmp"
                            }},
                            {"counter": "counter_ns_ba_ingress_ip6"},
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_ba_ingress,
                        "expr": [
                            {"counter": "counter_ns_ba_ingress_ethernet"}
                        ]}}
            },
            {'add': {'rule':
                     {
                         'family': family,
                         'table': table,
                         'chain': ns_bc_ingress,
                         "expr": [{
                             "match": {
                                 "op": "==",
                                 "left": {"payload": {"protocol": "ip", "field": "version"}},
                                 "right": 4
                             }},
                             {"counter": "counter_ns_bc_ingress_ip"}
                         ]}}
            },
            {'add': {'rule':
                     {
                         'family': family,
                         'table': table,
                         'chain': ns_bc_ingress,
                         "expr": [{
                             "match": {
                                 "op": "==",
                                 "left": {"payload": {"protocol": "arp", "field": "ptype"}},
                                 "right": "ip"
                             }},
                             {"counter": "counter_ns_bc_ingress_arp"}
                         ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_bc_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "protocol"}},
                                "right": "icmp"
                            }},
                            {"counter": "counter_ns_bc_ingress_icmp"}
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_bc_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "protocol"}},
                                "right": "tcp"
                            }},
                            {"counter": "counter_ns_bc_ingress_tcp"}
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_bc_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "protocol"}},
                                "right": "udp"
                            }},
                            {"counter": "counter_ns_bc_ingress_udp"}
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_bc_ingress,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip6", "field": "nexthdr"}},
                                "right": "ipv6-icmp"
                            }},
                            {"counter": "counter_ns_bc_ingress_ip6"},
                        ]}}
            },
            {'add': {'rule':
                    {
                        'family': family,
                        'table': table,
                        'chain': ns_bc_ingress,
                        "expr": [
                            {"counter": "counter_ns_bc_ingress_ethernet"}
                        ]}}
            },
            # {'add':{ 'rule': {
            #     'family': family,
            #     'table': table,
            #     'chain': fwd_chain_ac,
            #     'expr': [
            #         {
            #             'limit': {
            #                 'rate': bandwith_limit,
            #                 'per': 'second',
            #                 'rate_unit': 'bytes'
            #             }
            #         },
            #         { 'drop': "drop"}
            #     ]
            # }}
            # }
        ]


def print_table(json_data):

    nftables = json_data['nftables']
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


def compare_results(bandwith, blockcount, drop_rate, limit_rate_bytes_per_second, json_data):
    
    ######### IPERF3 VARIABLES ###########
    client_host = str(json_data['start']['connected'][0]['local_host'])+ ':' + str(json_data['start']['connected'][0]['local_port']) 
    server_host = str(json_data['start']['connected'][0]['remote_host'])+ ':' + str(json_data['start']['connected'][0]['remote_port']) 
    iperf_start_time = json_data['start']['timestamp']['time']
    iperf_protocol = json_data['start']['test_start']['protocol']
    iperf_blksize = json_data['start']['test_start']['blksize']
    iperf_duration_test = json_data['end']['sum']['seconds']
    iperf_bytes = json_data['end']['sum']['bytes']
    iperf_bits_per_sec = json_data['end']['sum']['bits_per_second']
    iperf_packets = json_data['end']['sum']['packets']
    iperf_packets_lost = json_data['end']['sum']['lost_packets']
    iperf_percent_lost = json_data['end']['sum']['lost_percent']

    ####### NFTABLES VARIABLES ###########
    nftables = json_data['nftables']
    nft_arp_packets = nftables[2]['counter']['packets'] 
    nft_arp_bytes =nftables[2]['counter']['bytes'] 
    nft_icmp_packets = nftables[3]['counter']['packets'] 
    nft_icmp_bytes = nftables[3]['counter']['bytes']
    nft_tcp_packets = nftables[4]['counter']['packets'] 
    nft_tcp_bytes = nftables[4]['counter']['bytes']
    nft_udp_packets = nftables[5]['counter']['packets'] 
    nft_udp_bytes = nftables[5]['counter']['bytes'] 
    nft_ip_packets = nftables[6]['counter']['packets'] 
    nft_ip_bytes = nftables[6]['counter']['bytes']
    nft_ip6_packets = nftables[7]['counter']['packets'] 
    nft_ip6_bytes = nftables[7]['counter']['bytes']
    nft_ethernet_packets = nftables[8]['counter']['packets'] 
    nft_ethernet_bytes = nftables[8]['counter']['bytes']
    nft_drop_dr_packets = nftables[9]['counter']['packets'] 
    nft_drop_dr_bytes = nftables[9]['counter']['bytes'] 
    nft_drop_lr_packets = nftables[10]['counter']['packets'] 
    nft_drop_lr_bytes = nftables[10]['counter']['bytes']
    nft_total_drop_packets = nft_drop_dr_packets + nft_drop_lr_packets
    nft_total_drop_bytes = nft_drop_dr_bytes + nft_drop_lr_bytes


    ############ PRINTING RESULTS ##############
    print(":------------- VERIFYING THE TEST OUTCOME -------------------:")
    logger.info(f'Test finished....')
    logger.info(f'{iperf_protocol} Packets sent from Client({client_host}) to Server({server_host})')
    logger.info(f'Execution time: {iperf_start_time} Duration: {iperf_duration_test} sec.')
    logger.info(f'Bits per second: {iperf_bits_per_sec}')

    logger.info('-----------------------------------------------------------------------------')
    
    # blockcount  should be equal to quantity of packets
    if int(blockcount) == int(iperf_packets):
        logger.info(f'{blockcount} {iperf_protocol} Packets sent by iperf Client (Block Size:{iperf_blksize})..........OK')
    else:
        logger.error(f'Number of {iperf_protocol} packets configured by user ({blockcount}) does not much with the packets sent ({iperf_packets})')     

    # iperf3 quantity of packet should be equal to the one received by BA_ETH
    # we know that the nftables counter see one extra UDP packet 
    if  ((nft_udp_packets - 1) - iperf_packets) == 0:
        logger.info(f'{nft_udp_packets} {iperf_protocol} Packets received in interface BA_ETH of the channel..........OK')
    else:
        logger.error(f'Number of {iperf_protocol} packets sent by iperf Client({iperf_packets}) does not much with the packets received in the interface BA_ETH ({nft_udp_packets})')  

    logger.info("")

    # iperf3 quantity of bytes should be equal to the one received by BA_ETH
    # nft_udp_bytes = (aprox)15000000 but we have 20 from ip header and 8 from udp header
    nft_udp_bytes = nft_udp_bytes-28*int(blockcount)

    if  ((nft_udp_bytes) - iperf_bytes) < iperf_bytes*0.05:
        logger.info(f'{iperf_bytes} bytes sent by iperf client ..........OK')
        logger.info(f'{nft_udp_bytes} bytes received in interface BA_ETH of the channel..........OK')
    
    else:
        logger.error(f'{iperf_bytes} bytes sent by iperf client')
        logger.error(f'# of  bytes sent by iperf Client ({iperf_bytes}) does not much with the bytes received in the interface BA_ETH ({nft_udp_bytes})')  

    logger.info('-----------------------------------------------------------------------------')

    # iperf3 quantity of packet loss should be equal to the lost ones in BA_ETH


    if nft_total_drop_packets - iperf_packets_lost == 0:
        logger.info(f'{iperf_packets_lost}({iperf_percent_lost}%) {iperf_protocol} Packets were not received by the iperf server..........OK')
        logger.info(f'{nft_total_drop_packets} {iperf_protocol} Packets dropped in interface BA_ETH of the channel..........OK')
        logger.info(f'{nft_total_drop_bytes} Bytes dropped in interface BA_ETH of the channel..........OK')
   
    elif (nft_total_drop_packets - iperf_packets_lost) < iperf_packets_lost*0.05:
        logger.warning(f'There is a difference of {nft_total_drop_packets - iperf_packets_lost} packets between iperf and nftables counters')
        logger.warning(f'{iperf_packets_lost}({iperf_percent_lost}%) {iperf_protocol} Packets were not received by the iperf server')
        logger.warning(f'{nft_total_drop_packets} {iperf_protocol} Packets dropped in interface BA_ETH of the channel')
        logger.warning(f'{nft_total_drop_bytes} Bytes dropped in interface BA_ETH of the channel')

    else:
        logger.error(f'{iperf_packets_lost}({iperf_percent_lost}%) {iperf_protocol} Packets were not received by the iperf server')
        logger.error(f'# of {iperf_protocol} packets sent by iperf Client ({iperf_packets}) does not match the packets received in the interface BA_ETH ({nft_udp_packets})')
        logger.error(f'{nft_total_drop_bytes} Bytes dropped in interface BA_ETH of the channel')

    logger.info("")

    # check if packet drop because of DR match with the drop rate configured by user
    if abs(nft_drop_dr_packets - (iperf_packets*drop_rate)) <= (iperf_packets*drop_rate)*0.05:
        logger.info(f'{nft_drop_dr_packets} {iperf_protocol} Packets dropped because of Drop Rate = {drop_rate}..........OK')
        logger.info(f'{nft_drop_dr_bytes} Bytes dropped because of Drop Rate = {drop_rate}..........OK')

    else:
        logger.error(f'{nft_drop_dr_packets} {iperf_protocol} Packets dropped because of Drop Rate = {drop_rate}')
        logger.error(f'{nft_drop_dr_bytes} Bytes dropped because of Drop Rate = {drop_rate}')

    logger.info("")

    # check if packet drop because of LR match with the limit rate configured by user
    # Bandwith = 10Mbit -- Limit Rate over = 1Mbit, only 10% of the packet pass 
    if abs(nft_udp_packets-nft_drop_lr_packets) <= iperf_packets*0.1:
        logger.info(f'{nft_drop_lr_packets} {iperf_protocol} Packets dropped because of Limit Rate = {limit_rate_bytes_per_second}..........OK')
        logger.info(f'{nft_drop_lr_bytes} Bytes dropped because of Limit Rate = {limit_rate_bytes_per_second}..........OK')
    

    elif nft_udp_packets-nft_drop_lr_packets == nft_udp_packets and limit_rate_bytes_per_second == 0:
        logger.info(f'{nft_drop_lr_packets} {iperf_protocol} Packets dropped because of Limit Rate = {limit_rate_bytes_per_second}..........OK')
        logger.info(f'{nft_drop_lr_bytes} Bytes dropped because of Limit Rate = {limit_rate_bytes_per_second}..........OK')
    
    else:
        logger.error(f'There should be around {int(iperf_packets*0.1)} {iperf_protocol} Packets dropped because of Limit Rate = {limit_rate_bytes_per_second} Bytes')
        logger.error(f'Number of {iperf_protocol} Packets dropped: {nft_drop_lr_packets} ')
        logger.error(f'Number of Bytes dropped: {nft_drop_lr_bytes} ')
       
    print(nft_udp_packets-nft_drop_lr_packets)
    print(nft_udp_packets)
    print(limit_rate_bytes_per_second)

@logger.catch
def nft_json_validate_and_run(nft, cmds):
    json_cmds = {'nftables': cmds}
    nft.json_validate(json_cmds)
    rc, output, error = nft.json_cmd(json_cmds)
    if rc != 0:
        logger.error(f'json_cmd: {error}')
        raise RuntimeError(f'nftables return code: {rc}')
    return output


@logger.catch
@app.command()
def test(bandwidth: str,
         blockcount: int = 10000,
         drop_rate: float = typer.Option(0, min=0, max=1),
         limit_rate_bytes_per_second: int = typer.Option(0, min=0, max=2**32 - 1)):
    logger.info(f'Test will run with <magenta>{bandwidth = }</>, <magenta>{blockcount = }</>, <magenta>{drop_rate = }</>, <magenta>{limit_rate_bytes_per_second = }</>')

    NFT_CONFIG.append(        
        {'add': {'rule': {
            'family': family,
            'table': table,
            'chain': fwd_chain_ac,
            'expr': [
                {
                    'match': {
                        'op': '<',
                        'left': {'numgen': {
                            'mode': 'random',
                            'mod': 1000,
                            'offset': 0
                        }
                        },
                        'right': int(drop_rate*1000)
                    }
                },
                {'counter': 'counter_ns_ba_ingress_dropped_by_packetloss'},
                {'drop': "drop"}
            ]
        }}
        })

    with netns.NetNS(nsname='ns_b'):
        nft = Nftables()
        nft.set_json_output(True)
        nft.cmd(
        '''
        flush ruleset
        add table netdev example
        add chain netdev example ns_ba_ingress { type filter hook ingress device ba_eth priority 0; policy accept; }
        add chain netdev example ns_bc_ingress { type filter hook ingress device bc_eth priority 0; policy accept; }
        add chain netdev example fwd_chain_ac { type filter hook ingress device ba_eth priority 1; policy accept; }
        add chain netdev example fwd_chain_ca { type filter hook ingress device bc_eth priority 1; policy accept; }
        ''')

        nft_json_validate_and_run(nft, NFT_CONFIG)

        cmd_string = ''
        if limit_rate_bytes_per_second > 0:
            cmd_string += f'add rule netdev example fwd_chain_ac limit rate over {limit_rate_bytes_per_second} bytes/second counter name counter_ns_ba_ingress_dropped_by_limit drop'
        cmd_string += '''
        add rule netdev example fwd_chain_ac fwd to bc_eth
        add rule netdev example fwd_chain_ca fwd to ba_eth
        '''
        # logger.debug(cmd_string)

        nft.cmd(cmd_string)
        # logger.debug(nft_json_validate_and_run(nft, [{'list': {'ruleset': None }}]))

    iperf3_cmd = f'-i 2 -c {IPERF3_SERVER} --json -u --udp-counters-64bit -b {bandwidth} --blockcount {blockcount} --length 1472'
    logger.debug(f'{iperf3_cmd = }')
    with netns.NetNS(nsname='ns_a'):
        try:
            ping(f'-w 3 -c 1 {IPERF3_SERVER}'.split())
        except ErrorReturnCode as erc:
            logger.error(f'ping to iperf3 server failed')
        try:
            r = iperf3(iperf3_cmd.split())
            r = json.loads(r.stdout)
        except ErrorReturnCode as e:
            typer.secho(f'Error: {e}', fg=typer.colors.RED)
            r = json.loads(e.stdout)

    with netns.NetNS(nsname='ns_b'):
        nft = Nftables()
        nft.set_json_output(True)
        output = nft_json_validate_and_run(nft, [{'list': {'ruleset': None }}])

    output_dictionary = {**output, **r}
    print_table(output_dictionary)

    compare_results(bandwidth, blockcount, drop_rate, limit_rate_bytes_per_second, output_dictionary)


if __name__ == '__main__':
    logger = logger.opt(ansi=True)
    logger = logger.patch(lambda r: r.update(name='Test'))
    logger.info('Started')

    app()
