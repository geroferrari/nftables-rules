#!venv/bin/python3
from time import sleep
from nftables import Nftables
import typer
import json
from sh import iperf3, ping, ErrorReturnCode, tc
import netns
import sys
from loguru import logger
from datetime import datetime
from pathlib import Path
from itertools import product
from functools import partial

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

SUITE = {
            #'rate': ['1g', '50g'],
            'rate': ['1g', '5g', '8g', '10g'],                    #bandwith
            #'protocol': ['UDP', 'TCP'],
            'protocol': ['UDP'],
            'parallel': [1, 4],
            #'parallel': [1, 2, 8],
            #'zerocopy': [False],
            # 'zerocopy': [True, False],
            'delay_ms': [0],
            'drop_rate': [0],
            'limit_rate_bytes_per_second' : [0],
            'blockcount' : [1000000]
        }


@logger.catch
def nft_json_validate_and_run(nft, cmds):
    json_cmds = {'nftables': cmds}
    nft.json_validate(json_cmds)
    rc, output, error = nft.json_cmd(json_cmds)
    if rc != 0:
        logger.error(f'json_cmd: {error}')
        raise RuntimeError(f'nftables return code: {rc}')
    return output


def test(rate, protocol, parallel, delay_ms, drop_rate, limit_rate_bytes_per_second, blockcount):

    args = f' -i 2 -Z -c {IPERF3_SERVER} -p 5104 --json -u --udp-counters-64bit' if protocol == 'UDP' else '-i 2 -c {IPERF3_SERVER} --json'

    args += f' -b {rate}'
    args += f' --blockcount {blockcount}'
    args += ' --length 1472'
    args += f' -P {parallel}'

    typer.secho(f'Testing for {args}', fg=typer.colors.GREEN)

    with netns.NetNS(nsname='ns_b'):
        try:
            if delay_ms > 0:
                tc(f'qdisc add dev ba_eth root netem delay {delay_ms}ms'.split())
                tc(f'qdisc add dev bc_eth root netem delay {delay_ms}ms'.split())
                tc(f'qdisc list'.split())

            nft = Nftables()
            nft.set_json_output(True)
            nft.cmd(
            '''
            flush ruleset
            add table netdev example
            add chain netdev example ns_ba_ingress { type filter hook ingress device ba_eth priority 0; policy accept; }
            add chain netdev example ns_bc_ingress { type filter hook ingress device bc_eth priority 0; policy accept; }
            ''')

        #    nft_json_validate_and_run(nft, NFT_CONFIG)

        #     cmd_string = ''
        #     if limit_rate_bytes_per_second > 0:
        #         cmd_string += f'add rule netdev example ns_ba_ingress limit rate over {limit_rate_bytes_per_second} bytes/second counter name counter_ns_ba_ingress_dropped_by_limit drop'
        #         nft.cmd(cmd_string)

        #     NFT_CONFIG_DR = [        
        #         {'add': {'rule': {
        #             'family': family,
        #             'table': table,
        #             'chain': ns_ba_ingress,
        #             'expr': [
        #                 {
        #                     'match': {
        #                         'op': '<',
        #                         'left': {'numgen': {
        #                             'mode': 'random',
        #                             'mod': 1000,
        #                             'offset': 0
        #                         }
        #                         },
        #                         'right': int(drop_rate*1000)
        #                     }
        #                 },
        #                 {'counter': 'counter_ns_ba_ingress_dropped_by_packetloss'},
        #                 {'drop': "drop"}
        #             ]
        #         }}
        #         }]

        #     nft_json_validate_and_run(nft, NFT_CONFIG_DR)

        #     cmd_string = '''
        #     add rule netdev example ns_ba_ingress fwd to bc_eth
        #     '''
        #     nft.cmd(cmd_string)

        #     cmd_string = ''
        #     if limit_rate_bytes_per_second > 0:
        #         cmd_string += f'add rule netdev example ns_bc_ingress limit rate over {limit_rate_bytes_per_second} bytes/second counter name counter_ns_bc_ingress_dropped_by_limit drop'
        #         nft.cmd(cmd_string)

        #     NFT_CONFIG_DR = [        
        #         {'add': {'rule': {
        #             'family': family,
        #             'table': table,
        #             'chain': ns_bc_ingress,
        #             'expr': [
        #                 {
        #                     'match': {
        #                         'op': '<',
        #                         'left': {'numgen': {
        #                             'mode': 'random',
        #                             'mod': 1000,
        #                             'offset': 0
        #                         }
        #                         },
        #                         'right': int(drop_rate*1000)
        #                     }
        #                 },
        #                 {'counter': 'counter_ns_bc_ingress_dropped_by_packetloss'},
        #                 {'drop': "drop"}
        #             ]
        #         }}
        #         }]

        #     nft_json_validate_and_run(nft, NFT_CONFIG_DR)

            cmd_string = '''
            add rule netdev example ns_ba_ingress fwd to bc_eth
            add rule netdev example ns_bc_ingress fwd to ba_eth
            '''
            nft.cmd(cmd_string)

        except ErrorReturnCode as e:
            typer.secho(f'Error: {e}', fg=typer.colors.RED)
            r = json.loads(e.stdout)



    logger.debug(f'{args = }')

    retries = 5
    with netns.NetNS(nsname='ns_a'):
        while retries > 0:
            try:
                r = iperf3(args.split())
                r = json.loads(r.stdout)
                retries = 0
            except ErrorReturnCode as e:
                typer.secho(f'Error: {e}', fg=typer.colors.RED)
                typer.secho(f'Retrying: {retries}', fg=typer.colors.RED)
                retries -= 1
                if retries == 0:
                    r = json.loads(e.stdout)


    with netns.NetNS(nsname='ns_b'):
        nft = Nftables()
        nft.set_json_output(True)
        if delay_ms > 0:
            tc(f'qdisc delete dev ba_eth root netem'.split())
            tc(f'qdisc delete dev bc_eth root netem'.split())
        output = nft_json_validate_and_run(nft, [{'list': {'ruleset': None }}])

    return {**output, **r}


@logger.catch
@app.command()
def test_suite():
    utc_now = datetime.utcnow()
    json_path = Path(f'./results/{utc_now:%Y.%m.%d.%H.%M.%S}_5104_results.json')
    typer.secho(f'Base iperf3 command: {iperf3}', fg=typer.colors.YELLOW)
    typer.secho(f'Test suite:\n{json.dumps(SUITE, indent=4)}', fg=typer.colors.YELLOW)

    try:
        targets = [dict(zip(SUITE.keys(), v)) for v in product(*SUITE.values())]
        results = [(target, partial(test)(**target)) for target in targets]
        typer.secho(f'Saving results to {json_path}', fg=typer.colors.YELLOW)
        with open(json_path, 'w') as f:
            f.write(json.dumps(results))
    
    except KeyboardInterrupt:
        typer.secho('\nInterrupted by user.', fg=typer.colors.RED)


if __name__ == '__main__':
    logger = logger.opt(ansi=True)
    logger = logger.patch(lambda r: r.update(name='Test'))
    logger.info('Started')
    app()
