#!/bin/bash -e

# lava-tools already downloaded in setup.sh

# Back up the keystore
./lava-tools/lava-persistent-storage/backup_file.sh /etc/itest /etc/*_hsm


