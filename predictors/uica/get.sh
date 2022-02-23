#!/bin/bash

INVENV=$(python -c 'import sys ; print( 0 if sys.prefix == sys.base_prefix else 1 )')

if [ "$INVENV" -ne 1 ]; then
    echo "Not running in a virtual environment!"
    exit 1
fi

set -ex

/usr/bin/env pip3 install plotly

git clone https://github.com/andreas-abel/uiCA.git repo

cd repo

# check out the version from the paper
git checkout 71f2eb6

./setup.sh

