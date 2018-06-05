curl -X POST --header "Transfer-Encoding: chunked" --header "X-ServerSide: 1" -H "Connection: keep-alive" -v --data-binary "" -s -b cookies -c cookies "http://192.168.56.101:80/poc.aspx"  2>&1
