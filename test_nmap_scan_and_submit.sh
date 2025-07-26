#!/bin/bash

curl -X POST http://localhost:8000/scan/process \
  -H "Content-Type: application/json" \
  -d '{
    "xml_content": "<nmaprun scanner=\"nmap\" start=\"1315618421\" version=\"5.59BETA3\"><host><address addr=\"192.168.1.100\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\" version=\"Apache 2.4.41\"/></port></ports></host></nmaprun>"
}'
