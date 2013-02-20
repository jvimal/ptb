#!/bin/bash

dev=eth2
tc qdisc del dev $dev root
rmmod sch_ptb
make
insmod ./sch_ptb.ko
tc qdisc add dev $dev root handle 1: tbf limit 100000 burst 1000 rate 3Gbit
