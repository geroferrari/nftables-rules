# nftableson

nftables python binding json config testing

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
