#!/usr/bin/bash
set -x
set -e

source ./_names.sh

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

# devices up
ip -n $NS_A link set dev ab_eth up
ip -n $NS_B link set dev ba_eth up
ip -n $NS_B link set dev bc_eth up
ip -n $NS_C link set dev cb_eth up

# IP assignment
ip -n $NS_A addr add 172.17.100.1/24 dev ab_eth
ip -n $NS_C addr add 172.17.100.2/24 dev cb_eth
