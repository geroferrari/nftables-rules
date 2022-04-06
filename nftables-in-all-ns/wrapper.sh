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

ip netns exec $NS_A ./ns_a_with_nft.nft
ip netns exec $NS_B ./ns_b_with_nft.nft
ip netns exec $NS_C ./ns_c_with_nft.nft

# Test if it really works
ip netns exec $NS_A ping -W 1 -c 10 172.17.100.2
#ip netns exec $NS_C ping -W 1 -c 1 172.17.100.1

ip netns exec $NS_A nft -j list ruleset | tee ns_a_output.json
ip netns exec $NS_B nft -j list ruleset | tee ns_b_output.json
ip netns exec $NS_C nft -j list ruleset | tee ns_c_output.json
# desactiva
set +x