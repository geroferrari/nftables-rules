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

### Test 1: 10 Ping from NS_A to NS_C: 
10 packets transmitted, 10 received, 0% packet loss, time 9202ms


Final state of the counters in NS_A 
```json
     {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_arp",
            "table":"example",
            "handle":5,
            "packets":2,
            "bytes":56
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_icmp",
            "table":"example",
            "handle":6,
            "packets":10,
            "bytes":840
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_tcp",
            "table":"example",
            "handle":7,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_udp",
            "table":"example",
            "handle":8,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_ip6",
            "table":"example",
            "handle":9,
            "packets":3,
            "bytes":184
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_received",
            "table":"example",
            "handle":10,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_dropped",
            "table":"example",
            "handle":11,
            "packets":0,
            "bytes":0
         }
      }
```

Final state of the counters in NS_C
```json
     {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_arp",
            "table":"example",
            "handle":12,
            "packets":2,
            "bytes":56
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_icmp",
            "table":"example",
            "handle":13,
            "packets":10,
            "bytes":840
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_tcp",
            "table":"example",
            "handle":14,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_udp",
            "table":"example",
            "handle":15,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_ip6",
            "table":"example",
            "handle":16,
            "packets":3,
            "bytes":184
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_received",
            "table":"example",
            "handle":17,
            "packets":10,
            "bytes":840
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_dropped",
            "table":"example",
            "handle":18,
            "packets":0,
            "bytes":0
         }
      }
```

| ingress  | NS_A | NS_C | info                                                          |
|----------|------|------|---------------------------------------------------------------|
| ARP      | 2    | 2    | "who has" from both sides and the answer                      |
| ICMP     | 10   | 10   | NS_A : 10 ICMP Echo reply NS_C : 10 ICMP Echo request         |
| TCP      | 0    | 0    |                                                               |
| UDP      | 0    | 0    |                                                               |
| IP6      | 3    | 3    |  ???                                                          |
| Received | 0    | 10   | Yhe packages go from A to C. So only the C counter is updated |
| Dropped  | 0    | 0    |                                                               |



### Test 2: 1 Ping from NS_A to NS_C &  1 Ping from NS_C to NS_A: 
PING 172.17.100.2 (172.17.100.2) 56(84) bytes of data.
1 packets transmitted, 1 received, 0% packet loss, time 0ms
--
PING 172.17.100.1 (172.17.100.1) 56(84) bytes of data.
1 packets transmitted, 1 received, 0% packet loss, time 0ms


Final state of the counters in NS_A 
```json
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_arp",
            "table":"example",
            "handle":5,
            "packets":1,
            "bytes":28
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_icmp",
            "table":"example",
            "handle":6,
            "packets":2,
            "bytes":168
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_tcp",
            "table":"example",
            "handle":7,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_udp",
            "table":"example",
            "handle":8,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_ip6",
            "table":"example",
            "handle":9,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_received",
            "table":"example",
            "handle":10,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_ingress_dropped",
            "table":"example",
            "handle":11,
            "packets":0,
            "bytes":0
         }
	  },
         "counter":{
            "family":"netdev",
            "name":"counter_ns_a_total",
            "table":"example",
            "handle":12,
            "packets":3,
            "bytes":196
         }
```

Final state of the counters in NS_C
```json
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_arp",
            "table":"example",
            "handle":12,
            "packets":1,
            "bytes":28
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_icmp",
            "table":"example",
            "handle":13,
            "packets":2,
            "bytes":168
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_tcp",
            "table":"example",
            "handle":14,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_udp",
            "table":"example",
            "handle":15,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_ip6",
            "table":"example",
            "handle":16,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_received",
            "table":"example",
            "handle":17,
            "packets":0,
            "bytes":0
         }
      },
      {
         "counter":{
            "family":"netdev",
            "name":"counter_ns_c_ingress_dropped",
            "table":"example",
            "handle":18,
            "packets":0,
            "bytes":0
         }
      },
	  "counter":{
            "family":"netdev",
            "name":"counter_ns_c_total",
            "table":"example",
            "handle":20,
            "packets":3,
            "bytes":196
         }
```

| ingress  | NS_A | NS_C | info                                     |
|----------|------|------|------------------------------------------|
| ARP      | 1    | 1    | *It is weird that there is only one*     |
| ICMP     | 2    | 2    | one echo request and one echo reply each |
| TCP      | 0    | 0    |                                          |
| UDP      | 0    | 0    |                                          |
| IP6      | 0    | 0    |                                          |
| Received | 0    | 0    | ???                                      |
| Dropped  | 0    | 0    |                                          |
| Total    | 3    | 3    |                                          |
