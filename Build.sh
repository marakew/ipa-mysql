#!/bin/sh
make clean
make -DWITHOUT_IP6FW -DWITHOUT_IPFIL -DWITH_MYSQL
