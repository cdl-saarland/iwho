#!/bin/bash

SRC_URL="https://uops.info/instructions.xml"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

DEST=$DIR/instructions.xml

curl -o $DEST $SRC_URL

