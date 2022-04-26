# nftables-rules

## Idea

Create 3 network namespaces (A, B & C) and 2 veth pairs for
making a "bridge" **B** between **A** and **C**.
This bridge can simulate frame loss due to random causes
and bandwith excess.

```
NETWORK A       |                    NETWORK B                    |   NETWORK C
-------------------------------------------------------------------------------
ab_eth       <--|--> ba_eth <-- nftables forwarding --> bc_eth <--|--> cb_eth
172.17.100.1/24 |                no IP assignment                 |    172.17.100.2/24
```

![Diagram](images/nftables.drawio.png "Diagram").

## Preparation

* `git clone https://github.com/geroferrari/nftables-rules`
* `cd nftables-rules`
* `python -m venv venv`
* `venv/bin/pip install -r reqs.txt`

## Usage

* `sudo tmuxinator start `
* <kbd>Ctrl</kbd> + <kbd>b</kbd>, release and
  * <kbd>d</kbd> for detach.
  * <kbd>z</kbd> for zoom current pane.
* `sudo tmuxinator stop nftables-rules`

## Results

* `venv/bin/python ./print_results.py results/2022.04.26.15.34.05_results.json `
