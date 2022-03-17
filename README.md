# nftableson

nftables python binding json config testing

## Idea

`wrapper.sh` creates 3 network namespaces (A, B & C) and 2 veth pairs
with the intention of creating a "bridge" **B** between **A** and **C**.

Then, using one of 3 methods (`with_cli.sh`, `with_python.py cmd` & `with_python.py json_cmd`),
two forwarding rules are created with `nftables`.

This project aims to show that one of those methods (`with_python.py json_cmd`)
does not work as intended.


```
NETWORK A       |                    NETWORK B                    |   NETWORK C
-------------------------------------------------------------------------------
ab_eth       <--|--> ba_eth <-- nftables forwarding --> bc_eth <--|--> cb_eth
172.17.100.1/24 |                no IP assignment                 |    172.17.100.2/24
```

## Preparation

* `git clone https://github.com/franalbani/nftableson.git`
* `cd nftableson`
* `python -m venv venv`
* `. venv/bin/activate`
* `pip install -r reqs.txt`
* `. venv/bin/deactivate`

## Run the tests

*(There is no need of activating python venv)*

These two works:

* `sudo ./wrapper.sh ./with_cli.sh`
* `sudo ./wrapper.sh ./with_python.py cmd`

This one does not work:

* `sudo ./wrapper.sh ./with_python.py json_cmd`

## Results

When it works, one can see that the chains are correctly associated with a device

```
table netdev example {
chain fwd_chain_ac {
type filter hook ingress device "ba_eth" priority filter + 1; policy accept;
fwd to "bc_eth"
}

chain fwd_chain_ca {
type filter hook ingress device "bc_eth" priority filter + 1; policy accept;
fwd to "ba_eth"
}
}
```

When it does not work, chains are empty:

```
table netdev example {
	chain fwd_chain_ac {
		fwd to "bc_eth"
	}

	chain fwd_chain_ca {
		fwd to "ba_eth"
	}
}
```

Another related bug is that the output of `nft.json_cmd({"nftables": [{"list": {"ruleset": None}}]})`
does not shows the device the chain is associated to:

```
{'nftables': [{'metainfo': {'json_schema_version': 1,
                            'release_name': 'Fearless Fosdick #3',
                            'version': '1.0.1'}},
              {'table': {'family': 'netdev', 'handle': 113, 'name': 'example'}},
              {'chain': {'family': 'netdev',
                         'handle': 1,
                         'hook': 'ingress',
                         'name': 'fwd_chain_ac',
                         'policy': 'accept',
                         'prio': 1,
                         'table': 'example',
                         'type': 'filter'}},
              {'rule': {'chain': 'fwd_chain_ac',
                        'expr': [{'fwd': {'dev': 'bc_eth'}}],
                        'family': 'netdev',
                        'handle': 3,
                        'table': 'example'}},
              {'chain': {'family': 'netdev',
                         'handle': 2,
                         'hook': 'ingress',
                         'name': 'fwd_chain_ca',
                         'policy': 'accept',
                         'prio': 1,
                         'table': 'example',
                         'type': 'filter'}},
              {'rule': {'chain': 'fwd_chain_ca',
                        'expr': [{'fwd': {'dev': 'ba_eth'}}],
                        'family': 'netdev',
                        'handle': 4,
                        'table': 'example'}}]}
```
