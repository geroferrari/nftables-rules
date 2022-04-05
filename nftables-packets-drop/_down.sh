#!/usr/bin/bash
set -x
set -e

source ./_names.sh

# Cleanup:
ip -n $NS_A link delete ab_eth # also deletes ba_eth
ip -n $NS_C link delete cb_eth # also deletes bc_eth

ip netns delete $NS_A
ip netns delete $NS_B
ip netns delete $NS_C

rm output.json