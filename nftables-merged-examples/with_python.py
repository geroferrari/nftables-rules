#!./venv/bin/python3
from doctest import Example
from traceback import print_tb
from nftables import Nftables
from pprint import pprint
import typer



app = typer.Typer()


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

    rc, output, error = nft.cmd(
    '''
    flush ruleset
    add table netdev example
    add chain netdev example ns_ba_ingress { type filter hook ingress device ba_eth priority 0; policy accept; }
    add chain netdev example ns_bc_ingress { type filter hook ingress device bc_eth priority 0; policy accept; }
    add chain netdev example fwd_chain_ac { type filter hook ingress device ba_eth priority 1; policy accept; }
    add chain netdev example fwd_chain_ca { type filter hook ingress device bc_eth priority 1; policy accept; }
    ''')

    rc, output, error = nft.json_cmd(NFT_CONFIG)

    cmd_string = '''\n
    add rule netdev example fwd_chain_ac limit rate over ''' + bandwith_limit +''' bytes/second counter name counter_ns_ba_ingress_dropped_by_limit drop \n
    add rule netdev example fwd_chain_ac fwd to bc_eth \n
    add rule netdev example fwd_chain_ca fwd to ba_eth \n
    '''

    rc, output, error = nft.cmd(cmd_string)

    if rc != 0:
        print(f'{rc = }')
        print(error)

if __name__ == '__main__':
    app()
