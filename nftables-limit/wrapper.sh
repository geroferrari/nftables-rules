#!/bin/bash

source ./_names.sh

# NETWORK A       |   NETWORK B                                     |   NETWORK C
#    ab_eth    <--|--> ba_eth <-- nftables forwarding --> bc_eth <--|--> cb_eth
# 172.17.100.1/24 |             no ip assignment                    | 172.17.100.2/24


# nftables command execution for setting the forwarding:
# $@ must be one of:
#   ./with_nft.nft

# set -x activa mostrar comando que se ejecuta
set -x

ip netns exec $NS_B $@

# Test if it really works
#ip netns exec $NS_A ping -W 1 -c 2 172.17.100.2
#ip netns exec $NS_A ping -W 1 -c 10 172.17.100.2

ip netns exec $NS_B nft list ruleset
ip netns exec $NS_B tcpdump -i ba_eth

# desactiva
set +x
