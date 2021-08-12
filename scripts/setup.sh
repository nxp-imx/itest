#!/bin/bash -e

# Get lava-tools
cat /opt/lava-tools.tar.bz2 | bzip2 -cd | tar xvf -

# Back up the keystore
./lava-tools/lava-persistent-storage/restore_file.sh /etc/itest /etc/v2x_hsm /etc/seco_hsm


