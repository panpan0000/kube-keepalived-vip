#!/bin/bash

TYPE="$1"
NAME="$2"
STATE="$3"

echo -n "${STATE}" > /var/run/keepalived-l7.state
exit 0

