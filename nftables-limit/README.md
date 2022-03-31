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


* `sudo ./wrapper.sh ./with_nft.nft`


## Results

When it works, one can see the quantity of packets and bytes.


```
--- 172.17.100.2 ping statistics ---
1000 packets transmitted, 843 received, 15,7% packet loss, time 2624ms
rtt min/avg/max/mdev = 0.003/0.034/0.149/0.034 ms, ipg/ewma 2.627/0.024 ms
PING 172.17.100.1 (172.17.100.1) 56(84) bytes of data.

--- 172.17.100.1 ping statistics ---
1000 packets transmitted, 858 received, 14,2% packet loss, time 2347ms
rtt min/avg/max/mdev = 0.005/0.031/0.360/0.033 ms, ipg/ewma 2.349/0.022 ms
table netdev example {
	counter counter_ac {
		packets 1907 bytes 160060
	}

	counter counter_ca {
		packets 1952 bytes 163840
	}

	chain fwd_chain_ac {
		type filter hook ingress device "ba_eth" priority filter + 1; policy accept;
		counter name "counter_ac"
		numgen random mod 100 < 5 drop
		fwd to "bc_eth"
	}

	chain fwd_chain_ca {
		type filter hook ingress device "bc_eth" priority filter + 1; policy accept;
		counter name "counter_ca"
		numgen random mod 100 < 10 drop
		fwd to "ba_eth"
	}
}

```

##  ISSUE: 
They are not converging to the value I set.

