#!/bin/bash

function get_container_ip() {
	local ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1")
	echo "$ip"

}

[ -n "$1" ] &&  get_container_ip "$1" || echo "Enter container name"
