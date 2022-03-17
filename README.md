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

## Run the tests

These two works:

* `sudo ./wrapper.sh ./with_cli.sh`
* `sudo ./wrapper.sh ./with_python.py cmd`

This one does not work:

* `sudo ./wrapper.sh ./with_python.py json_cmd`
