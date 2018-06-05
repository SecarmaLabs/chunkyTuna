#!/bin/bash
export WEBSHELL=$(./demo/get-container-ip.sh listener-jsp)
./chunkytuna.py http://$WEBSHELL:8080/c/chunkytuna.jsp X -r 127.0.0.1:12345 -t # COMMAND GOES HERE
