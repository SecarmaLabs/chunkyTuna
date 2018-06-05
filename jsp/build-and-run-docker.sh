#!/bin/sh
docker build -t listener-jsp .
docker run -it --rm -v $(pwd):/usr/local/tomcat/webapps/c --name listener-jsp listener-jsp
