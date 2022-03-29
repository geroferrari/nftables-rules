#!/bin/bash

nft flush ruleset

nft add table netdev example

nft add counter netdev example counter_ac 

nft add counter netdev example counter_ca 

nft add chain netdev example fwd_chain_ac \
    '{ type filter hook ingress device ba_eth priority 1; policy accept;}'

nft add chain netdev example fwd_chain_ca \
    '{ type filter hook ingress device bc_eth priority 1; policy accept;}'




#nft add rule netdev example fwd_chain_ac ip protocol icmp counter name counter_ac 
#nft add rule netdev example fwd_chain_ac ip protocol udp counter name counter_ac 
#nft add rule netdev example fwd_chain_ac tcp dport 22 counter name counter_ac accept

nft add rule netdev example fwd_chain_ca counter name counter_ac
nft add rule netdev example fwd_chain_ca counter name counter_ca
nft add rule netdev example fwd_chain_ac fwd to bc_eth 
nft add rule netdev example fwd_chain_ca fwd to ba_eth 