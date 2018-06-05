#!/bin/sh
docker build -t listener-php .
docker run -it --rm -v $(pwd):/var/www/html --name listener-php listener-php
echo "Don't forget to allow inbound connections from interface docker0"
