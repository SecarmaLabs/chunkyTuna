#!/bin/sh
docker build -t target .
docker run -it --rm -v $PWD:/foo -h target --name target target

