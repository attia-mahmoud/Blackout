#!/bin/bash

# sudo su

iptables -A FORWARD -s 192.168.1.2/32 -d 192.168.1.4/32 -j ACCEPT

iptables -A FORWARD -p icmp -d 192.168.1.4/32 -j ACCEPT

iptables -A FORWARD -d 192.168.1.4/32 -j DROP

echo "Rules added!"
