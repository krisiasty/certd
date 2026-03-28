#!/bin/bash

sudo mkdir -m 0755 -p /etc/sysusers.d

# create config for the user account
sudo tee /etc/sysusers.d/certd.conf <<EOF
# Type Name     ID    GECOS                 Home            Shell
u      certd    -     "certd service user"  /nonexistent    /usr/sbin/nologin
EOF

# activate creation of the user account
sudo systemd-sysusers

# check id of the account
id certd
