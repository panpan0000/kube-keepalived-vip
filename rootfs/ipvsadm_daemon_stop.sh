#!/bin/bash
set +e
ipvsadm --stop-daemon master
ipvsadm --stop-daemon backup


