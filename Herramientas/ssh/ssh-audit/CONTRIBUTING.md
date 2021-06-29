# Contributing to ssh-audit

We are very much open to receiving patches from the community!  To encourage participation, passing Travis tests, unit tests, etc., *is OPTIONAL*.  As long as the patch works properly, it can be merged.

However, if you can submit patches that pass all of our automated tests, then you'll lighten the load for the project maintainer (who already has enough to do!).  This document describes what tests are done and what documentation is maintained.

*Anything extra you can do is appreciated!*


## Tox Tests

Tox is used to do unit testing, linting with [pylint](http://pylint.pycqa.org/en/latest/) & [flake8](https://flake8.pycqa.org/en/latest/), and static type-checking with [mypy](https://mypy.readthedocs.io/en/stable/).

### Running tests on Ubuntu 18.04 and later

For Ubuntu 18.04 or later, install tox with `apt install tox`, then simply run `tox` in the top-level directory.  Look for any error messages in the (verbose) output.

### Running tests on Ubuntu 16.04

For Ubuntu 16.04 (which is still supported until April 2021), a newer version of tox is needed.  The easiest way is to use virtualenv:
```
$ sudo apt install python3-virtualenv
$ virtualenv -p /usr/bin/python3 ~/venv_ssh-audit
$ source ~/venv_ssh-audit/bin/activate
$ pip install tox
```
Then, to run the tox tests:
```
$ source ~/venv_ssh-audit/bin/activate
$ cd path/to/ssh-audit
$ tox
```


## Docker Tests

Docker is used to run ssh-audit against various real SSH servers (OpenSSH, Dropbear, and TinySSH).  The output is then diff'ed against the expected result.  Any differences result in failure.

The docker tests are run with `./docker_test.sh`.  The first time it is run, it will download and compile the SSH servers; this may take awhile.  Subsequent runs, however, will take only a minute to complete, as the docker image will already be up-to-date.


## Man Page

The `ssh-audit.1` man page documents the various features of ssh-audit.  If features are added, or significant behavior is modified, the man page needs to be updated.
