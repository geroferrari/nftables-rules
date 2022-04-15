#!./venv/bin/python3
from time import sleep
from xmlrpc.client import boolean
from nftables import Nftables
import typer
import json
import inotify.adapters
import os
import netns
from sh import iperf3

app = typer.Typer()

# i = inotify.adapters.Inotify()
# i.add_watch('output.json')


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

NFT_CONFIG = {'nftables':
        [
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
        ]}

nft = Nftables()


# def print_table():
#     with open('output.json', 'r') as f:
#         json_data = json.load(f)

#     print ("{:<10} | {:<21} | {:<21} |".format('Ingress', 'BA_ETH', 'BC_ETH'))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('', 'packets', 'Bytes', 'packets', 'Bytes'))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('ARP', json_data['nftables'][2]['counter']['packets'] , json_data['nftables'][2]['counter']['bytes'] , json_data['nftables'][11]['counter']['packets'], json_data['nftables'][11]['counter']['bytes'] ))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('ICMP', json_data['nftables'][3]['counter']['packets'] , json_data['nftables'][3]['counter']['bytes'],  json_data['nftables'][12]['counter']['packets'], json_data['nftables'][12]['counter']['bytes'] ))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('TCP', json_data['nftables'][4]['counter']['packets'] , json_data['nftables'][4]['counter']['bytes'],  json_data['nftables'][13]['counter']['packets'], json_data['nftables'][13]['counter']['bytes'] ))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('UDP', json_data['nftables'][5]['counter']['packets'] , json_data['nftables'][5]['counter']['bytes'],  json_data['nftables'][14]['counter']['packets'], json_data['nftables'][14]['counter']['bytes'] ))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('IP', json_data['nftables'][6]['counter']['packets'] , json_data['nftables'][6]['counter']['bytes'],  json_data['nftables'][15]['counter']['packets'], json_data['nftables'][15]['counter']['bytes'] ))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('IP6', json_data['nftables'][7]['counter']['packets'] , json_data['nftables'][7]['counter']['bytes'],  json_data['nftables'][16]['counter']['packets'], json_data['nftables'][16]['counter']['bytes'] ))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Ethernet', json_data['nftables'][8]['counter']['packets'] , json_data['nftables'][8]['counter']['bytes'],  json_data['nftables'][17]['counter']['packets'], json_data['nftables'][17]['counter']['bytes']))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Dropped PL', json_data['nftables'][9]['counter']['packets'] , json_data['nftables'][9]['counter']['bytes'],  json_data['nftables'][18]['counter']['packets'], json_data['nftables'][18]['counter']['bytes'] ))
#     print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Dropped L', json_data['nftables'][10]['counter']['packets'] , json_data['nftables'][10]['counter']['bytes'],  json_data['nftables'][19]['counter']['packets'], json_data['nftables'][19]['counter']['bytes'] ))
#     print (":-------------------------------------------------------------:")


@app.command()
def test(packet_loss: int, bandwith_limit: str):

    nft.set_json_output(True)

    NFT_CONFIG['nftables'].append(        
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
                        'right': packet_loss
                    }
                },
                {'counter': 'counter_ns_ba_ingress_dropped_by_packetloss'},
                {'drop': "drop"}
            ]
        }}
        },)

    nft.json_validate(NFT_CONFIG)

    nft.cmd(
    '''
    flush ruleset
    add table netdev example
    add chain netdev example ns_ba_ingress { type filter hook ingress device ba_eth priority 0; policy accept; }
    add chain netdev example ns_bc_ingress { type filter hook ingress device bc_eth priority 0; policy accept; }
    add chain netdev example fwd_chain_ac { type filter hook ingress device ba_eth priority 1; policy accept; }
    add chain netdev example fwd_chain_ca { type filter hook ingress device bc_eth priority 1; policy accept; }
    ''')

    nft.json_cmd(NFT_CONFIG)

    cmd_string = '''\n
    add rule netdev example fwd_chain_ac limit rate over ''' + bandwith_limit +''' bytes/second counter name counter_ns_ba_ingress_dropped_by_limit drop \n
    add rule netdev example fwd_chain_ac fwd to bc_eth \n
    add rule netdev example fwd_chain_ca fwd to ba_eth \n
    '''

    nft.cmd(cmd_string)

    iperf3 = iperf3.bake('-i 2 -t 10 -c 172.17.100.2 -u --udp-counters-64bit -b 100m --json'.split())

    with netns.NetNS(nsname='ns_a'):
        typer.secho(f'Base iperf3 command: {iperf3}', fg=typer.colors.YELLOW)
 

    # for event in i.event_gen(yield_nones=False):
    #     (_, type_names, path, filename) = event
    #     print("estoy aca")
    #     print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
    #     path, filename, type_names))
    #     if type_names == 'IN_MODIFY':
    #         print_table()   


if __name__ == '__main__':
    app()


