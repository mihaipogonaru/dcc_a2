#!/bin/bash

REQ="GET / HTTP/1.1\r\nUser-Agent: Wget/1.20.1 (linux-gnu)\r\nAccept: */*\r\nHost: 10.1.0.2\r\nConnection: Keep-Alive\r\n\r\n"
echo -ne $REQ; sleep 2; echo -ne $REQ; sleep 4; echo -ne $REQ; sleep 8; echo -ne $REQ | netcat 10.1.0.2 80
