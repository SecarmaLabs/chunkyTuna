#!/bin/sh
sudo ifconfig vboxnet0 192.168.56.1 up && sudo iptables -A INPUT -i vboxnet0 -j ACCEPT
sudo iptables -A INPUT -i docker0 -j ACCEPT
