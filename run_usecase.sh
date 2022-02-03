#!/bin/bash

TARGET="/usr/local/bin/soc_siemapp_elk"
CONFIG="/etc/soc_siemapp_elk/config.json"
LOGFILE="/var/log/soc_siemapp_elk.log"

$TARGET --logfile ${LOGFILE} --config ${CONFIG} run ${1} --notify
