#!/bin/bash
export WEBSHELL=$(./demo/get-container-ip.sh listener-jsp)
export TARGET=$(./demo/get-container-ip.sh target)
# listen on port 12345 on the remote, connect to 4444 on the local
./chunkytuna.py http://$WEBSHELL:8080/c/chunkytuna.jsp -r 127.0.0.1:4444 -t 0.0.0.0:12345 L $*
