# HTTPS Web Server

Highlights:
* The implementations for HTTP/1.1 and TLS/1.2 are my own.
* I am using my own finite elliptic curve group implementations for TLS key-exchange and signatures.
* I have used C++20 coroutines to finesse control-flow, [improving](https://github.com/fwoodruff/https-archive) bulk file transfer latency.
* The server runs at freddiewoodruff.co.uk on my Raspberry Pi 1B.
* The C++20 executable was cross-compiled for the Raspberry Pi on an AWS EC2 instance.

Out on the web there are bots probing every attack surface within the HTTP and TLS layers.
This has thrown up many curiosities and helped me harden the server.

