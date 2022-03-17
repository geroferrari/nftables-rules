#!./venv/bin/python3
from nftables import Nftables
from pprint import pprint
from sys import argv as arguments


family = 'netdev'
table = 'example'
fwd_chain_ac = 'fwd_chain_ac'
fwd_chain_ca = 'fwd_chain_ca'
chain_type = 'filter'
hook = 'ingress'
dev_ba = 'ba_eth'
dev_bc = 'bc_eth'
priority = 1
policy = 'accept'


NFT_CONFIG = {'nftables':
        [
            {'add': {'table':
                {
                    'family': family,
                    'name': table,
                }
            }},
            {'add': {'chain':
                {
                    'family': family,
                    'table': table,
                    'name': fwd_chain_ac,
                    'type': chain_type,
                    'hook': hook,
                    'device': dev_ba,
                    'priority': priority,
                    'policy': policy,
                }
            }},
            {'add': {'chain':
                {
                    'family': family,
                    'table': table,
                    'name': fwd_chain_ca,
                    'type': chain_type,
                    'hook': hook,
                    'device': dev_bc,
                    'priority': priority,
                    'policy': policy,
                }
            }},
            {'add': {'rule':
                {
                    'family': family,
                    'table': table,
                    'chain': fwd_chain_ac,
                    'expr': [{'fwd': {'dev': 'bc_eth'}}],
                }
            }},
            {'add': {'rule':
                {
                    'family': family,
                    'table': table,
                    'chain': fwd_chain_ca,
                    'expr': [{'fwd': {'dev': 'ba_eth'}}],
                }
            }},
        ]}

nft = Nftables()
nft.set_json_output(True)

nft.json_validate(NFT_CONFIG)

if len(arguments) != 2:
    raise ValueError('argument must be json_cmd or cmd')

if arguments[1] == 'json_cmd':
    rc, output, error = nft.json_cmd(NFT_CONFIG)
elif 'cmd':
    rc, output, error = nft.cmd(
    '''
    flush ruleset
    add table netdev example
    add chain netdev example fwd_chain_ac { type filter hook ingress device ba_eth priority 1; policy accept; }
    add chain netdev example fwd_chain_ca { type filter hook ingress device bc_eth priority 1; policy accept; }
    add rule netdev example fwd_chain_ac fwd to bc_eth
    add rule netdev example fwd_chain_ca fwd to ba_eth
    ''')
else:
    raise ValueError('argument must be json_cmd or cmd')

if rc != 0:
    print(f'{rc = }')
    print(error)

print('=== nft.json_cmd({"nftables": [{"list": {"ruleset": None}}]}) ===')
_, output, _ = nft.json_cmd({'nftables': [{'list': {'ruleset': None}}]})
pprint(output)
