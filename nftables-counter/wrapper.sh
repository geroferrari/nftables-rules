#!/bin/bash

# NETWORK A       |   NETWORK B                                     |   NETWORK C
#    ab_eth    <--|--> ba_eth <-- nftables forwarding --> bc_eth <--|--> cb_eth
# 172.17.100.1/24 |             no ip assignment                    | 172.17.100.2/24

NS_A='ns_a'
NS_B='ns_b'
NS_C='ns_c'


# Network namespaces creation
ip netns add $NS_A
ip netns add $NS_B
ip netns add $NS_C

# Virtual ethernet pairs creation
ip link add ab_eth type veth peer name ba_eth
ip link add bc_eth type veth peer name cb_eth

# VETHs namespace relocation
ip link set ab_eth netns $NS_A
ip link set ba_eth netns $NS_B
ip link set bc_eth netns $NS_B
ip link set cb_eth netns $NS_C

# IP assignment
ip -n $NS_A link set dev ab_eth up
ip -n $NS_B link set dev ba_eth up
ip -n $NS_B link set dev bc_eth up
ip -n $NS_C link set dev cb_eth up

ip -n $NS_A addr add 172.17.100.1/24 dev ab_eth
ip -n $NS_C addr add 172.17.100.2/24 dev cb_eth


# nftables command execution for setting the forwarding:
# $@ must be one of:
#   ./with_nft.nft


ip netns exec $NS_B $@

echo ================================
echo after wrapping: nft list ruleset
echo ================================


#sleep 30
#sudo ip netns exec ns_b tcpdump -i ba_eth -nn

#ip netns list
#ip netns exec $NS_B ip link

# Test if it really works
ip netns exec $NS_A ping -W 1 -c 1 172.17.100.2
ip netns exec $NS_C ping -W 1 -c 1 172.17.100.1


#ip netns exec $NS_B nft -j list ruleset
ip netns exec $NS_B nft list ruleset


echo ================================
echo reseting the following counters...
echo ================================
ip netns exec $NS_B nft reset counters


# Cleanup:
ip -n $NS_A link delete ab_eth # also deletes ba_eth
ip -n $NS_C link delete cb_eth # also deletes bc_eth
ip netns delete $NS_A
ip netns delete $NS_B
ip netns delete $NS_C
