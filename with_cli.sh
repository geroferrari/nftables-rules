#!/bin/bash

nft flush ruleset

nft add table netdev example

nft add chain netdev example fwd_chain_ac \
    '{ type filter hook ingress device ba_eth priority 1; policy accept;}'

nft add chain netdev example fwd_chain_ca \
    '{ type filter hook ingress device bc_eth priority 1; policy accept;}'

nft add rule netdev example fwd_chain_ac counter 
nft add rule netdev example fwd_chain_ca counter 
nft add rule netdev example fwd_chain_ac fwd to bc_eth 
nft add rule netdev example fwd_chain_ca fwd to ba_eth 

