#!/bin/bash -e

# Get lava-tools
wget --no-check-certificate -q -O - https://bamboo1.sw.nxp.com/browse/IM-LPLT2/latest/artifact/shared/lava-tools/lava-tools.tar.bz2 | bzip2 -cd | tar xvf -

# Back up the keystore
./lava-tools/lava-persistent-storage/restore_file.sh /etc/itest /etc/v2x_hsm


