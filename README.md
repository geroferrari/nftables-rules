# nftables - Counter
This projects aims to show how counter extension for nftables works. 

## Idea

`wrapper.sh` creates 3 network namespaces (A, B & C) and 2 veth pairs
with the intention of creating a "bridge" **B** between **A** and **C**.

Then, using `with_cli.sh` two forwarding rules are created with `nftables`.


```
NETWORK A       |                    NETWORK B                    |   NETWORK C
-------------------------------------------------------------------------------
ab_eth       <--|--> ba_eth <-- nftables forwarding --> bc_eth <--|--> cb_eth
172.17.100.1/24 |                no IP assignment                 |    172.17.100.2/24
```

## Preparation

* `git clone https://github.com/geroferrari/nftables-counter`
* `cd nftables-counter`

## Run the tests

*(There is no need of activating python venv)*


* `sudo ./wrapper.sh ./with_cli.sh`


## Results

When it works, one can see the quantity of packets and bytes.


```
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.029/0.029/0.029/0.000 ms
table netdev example {
	chain fwd_chain_ac {
		type filter hook ingress device "ba_eth" priority filter + 1; policy accept;
		counter packets 3 bytes 196
		fwd to "bc_eth"
	}

	chain fwd_chain_ca {
		type filter hook ingress device "bc_eth" priority filter + 1; policy accept;
		counter packets 3 bytes 196
		fwd to "ba_eth"
	}
}
```

