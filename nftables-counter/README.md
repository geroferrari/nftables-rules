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

## Execute
* `sudo ./wrapper.sh ./with_nft.nft `


* `sudo tmuxinator start`
* `CTRL+b d` para detach
* `sudo tmuxinator stop counters`


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


##  TEST:

### Test 1: 3 Ping from NS_A to NS_C: 
3 packets transmitted, 3 received, 0% packet loss, time 9202ms
(IP6 packets are dropped)

|  Ingress |      BA_ETH      |      BC_ETH      |
|:--------:|:----------------:|:----------------:|
|          | packets    Bytes | packets    Bytes |
| ARP      | 1          28    | 1          28    |
| ICMP     | 3          252   | 3          252   |
| TCP      | 0          0     | 0          0     |
| UDP      | 0          0     | 0          0     |
| IP       | 3          252   | 3          252   |
| IP6      | 2          128   | 2          128   |
| Ethernet | 7          508   | 7          508   |
| Dropped  | 0          0     | 0          0     |

### Test 2: 1 Ping from NS_A to NS_C &  1 Ping from NS_C to NS_A: 
PING 172.17.100.2 (172.17.100.2) 56(84) bytes of data.
1 packets transmitted, 1 received, 0% packet loss, time 0ms
--
PING 172.17.100.1 (172.17.100.1) 56(84) bytes of data.
1 packets transmitted, 1 received, 0% packet loss, time 0ms

|  Ingress |      BA_ETH      |      BC_ETH      |
|:--------:|:----------------:|:----------------:|
|          | packets    Bytes | packets    Bytes |
| ARP      | 1          28    | 1          28    |
| ICMP     | 2          168   | 2          168   |
| TCP      | 0          0     | 0          0     |
| UDP      | 0          0     | 0          0     |
| IP       | 2          168   | 2          168   |
| IP6      | 0          0     | 0          0     |
| Ethernet | 3          196   | 3          196   |
