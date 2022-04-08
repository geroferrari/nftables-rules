# nftables - merged-examples
This projects aims to show how counter extension for nftables works. 

## Idea

`wrapper.sh` creates 3 network namespaces (A, B & C) and 2 veth pairs
with the intention of creating a "bridge" **B** between **A** and **C**.

Then, using `with_python.sh` two forwarding rules are created with `nftables`.


```
NETWORK A       |                    NETWORK B                    |   NETWORK C
-------------------------------------------------------------------------------
ab_eth       <--|--> ba_eth <-- nftables forwarding --> bc_eth <--|--> cb_eth
172.17.100.1/24 |                no IP assignment                 |    172.17.100.2/24
```

## Preparation

* `git clone https://github.com/geroferrari/nftables-rules

## Execute

* `sudo tmuxinator start`
* `CTRL+b d` para detach
* `sudo tmuxinator stop limit`

## Questions

- How to send the arguments through the tmuxinator?
- How to wait until the iperf3 test finish to execute the output.py
- is it possible to add the limit rule as a json?



## Results
