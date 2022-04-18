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
                            {"drop": "drop"}
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
                            {"drop": "drop"}
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

    print(":------------- NFTABLES NS_B BA_ETH INGRESS -------------------:")
    print ("{:<10} | {:<21} | {:<21} |".format('Ingress', 'BA_ETH', 'BC_ETH'))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('', 'packets', 'Bytes', 'packets', 'Bytes'))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('ARP', json_data['nftables'][2]['counter']['packets'] , json_data['nftables'][2]['counter']['bytes'] , json_data['nftables'][11]['counter']['packets'], json_data['nftables'][11]['counter']['bytes'] ))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('ICMP', json_data['nftables'][3]['counter']['packets'] , json_data['nftables'][3]['counter']['bytes'],  json_data['nftables'][12]['counter']['packets'], json_data['nftables'][12]['counter']['bytes'] ))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('TCP', json_data['nftables'][4]['counter']['packets'] , json_data['nftables'][4]['counter']['bytes'],  json_data['nftables'][13]['counter']['packets'], json_data['nftables'][13]['counter']['bytes'] ))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('UDP', json_data['nftables'][5]['counter']['packets'] , json_data['nftables'][5]['counter']['bytes'],  json_data['nftables'][14]['counter']['packets'], json_data['nftables'][14]['counter']['bytes'] ))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('IP', json_data['nftables'][6]['counter']['packets'] , json_data['nftables'][6]['counter']['bytes'],  json_data['nftables'][15]['counter']['packets'], json_data['nftables'][15]['counter']['bytes'] ))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('IP6', json_data['nftables'][7]['counter']['packets'] , json_data['nftables'][7]['counter']['bytes'],  json_data['nftables'][16]['counter']['packets'], json_data['nftables'][16]['counter']['bytes'] ))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Ethernet', json_data['nftables'][8]['counter']['packets'] , json_data['nftables'][8]['counter']['bytes'],  json_data['nftables'][17]['counter']['packets'], json_data['nftables'][17]['counter']['bytes']))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Dropped DR', json_data['nftables'][9]['counter']['packets'] , json_data['nftables'][9]['counter']['bytes'],  json_data['nftables'][18]['counter']['packets'], json_data['nftables'][18]['counter']['bytes'] ))
    print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Dropped LR', json_data['nftables'][10]['counter']['packets'] , json_data['nftables'][10]['counter']['bytes'],  json_data['nftables'][19]['counter']['packets'], json_data['nftables'][19]['counter']['bytes'] ))
    print (":-------------------------------------------------------------:")
    print("")



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
    
    # blockcount  should be equal to # of packets
    if int(blockcount) == int(iperf_packets):
        logger.info(f'{blockcount} {iperf_protocol} Packets sent by iperf Client (Block Size:{iperf_blksize})..........OK')
    else:
        logger.warning(f'# of {iperf_protocol} packets configured by user ({blockcount}) does not much with the packets sent ({iperf_packets})')     

    # iperf3 # of packet should be equal to the one received by BA_ETH
    if  (nft_udp_packets - iperf_packets) < iperf_packets*0.05:
        logger.info(f'{nft_udp_packets} {iperf_protocol} Packets received in interface BA_ETH of the channel..........OK')
    else:
        logger.warning(f'# of {iperf_protocol} packets sent by iperf Client({iperf_packets}) does not much with the packets received in the interface BA_ETH ({nft_udp_packets})')  

    logger.info("")

    # iperf3 # of bytes should be equal to the one received by BA_ETH
    nft_udp_bytes = nft_udp_bytes-28*int(blockcount)

    if  ((nft_udp_bytes) - iperf_bytes) < iperf_bytes*0.05:
        logger.info(f'{iperf_bytes} bytes sent by iperf client ..........OK')
        logger.info(f'{nft_udp_bytes} bytes received in interface BA_ETH of the channel..........OK')
    else:
        logger.warning(f'# of  bytes sent by iperf Client ({iperf_bytes}) does not much with the bytes received in the interface BA_ETH ({nft_udp_bytes})')  

    logger.info('-----------------------------------------------------------------------------')

    # iperf3 # of packet loss should be equal to the lost ones in BA_ETH
    if  (nft_total_drop_packets - iperf_packets_lost) < iperf_packets_lost*0.05:
        logger.info(f'{iperf_packets_lost}({iperf_percent_lost}%) {iperf_protocol} Packets were not received by the iperf server..........OK')
        logger.info(f'{nft_total_drop_packets} {iperf_protocol} Packets dropped in interface BA_ETH of the channel..........OK')
        logger.info(f'{nft_drop_dr_packets} {iperf_protocol} Packets dropped because of Drop Rate = {drop_rate}..........OK')
        logger.info(f'{nft_drop_lr_packets} {iperf_protocol} Packets dropped because of Limit Rate = {limit_rate_bytes_per_second}..........OK')
        
        logger.info("")
        
        logger.info(f'{nft_total_drop_bytes} Bytes dropped in interface BA_ETH of the channel..........OK')
        logger.info(f'{nft_drop_dr_bytes} Bytes Packets dropped because of Drop Rate = {drop_rate}..........OK')
        logger.info(f'{nft_drop_lr_bytes} Bytes dropped because of Limit Rate = {limit_rate_bytes_per_second}..........OK')

    else:
        logger.warning(f'# of {iperf_protocol} packets sent by iperf Client ({iperf_packets}) does not match the packets received in the interface BA_ETH ({nft_udp_packets})')


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
                        'right': int(drop_rate)
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
