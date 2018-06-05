#!/bin/bash
export WEBSHELL=$(./demo/get-container-ip.sh listener-jsp)
export TARGET=$(./demo/get-container-ip.sh target)
# connect to target port 80
./chunkytuna.py http://$WEBSHELL:8080/c/chunkytuna.jsp -r 127.0.0.1:4444 -t $TARGET:80 C
# connect to target port 22
./chunkytuna.py http://$WEBSHELL:8080/c/chunkytuna.jsp -r 127.0.0.1:4444 -t $TARGET:22 C
