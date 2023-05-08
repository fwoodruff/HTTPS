# HTTPS Web Server

The implementations for HTTP/1.1 and TLS/1.2 are my own. I am using my own finite elliptic curve group implementations
for TLS key-exchange and signatures.

My original C++17 server is [here](https://github.com/fwoodruff/https-archive).
I have used C++20 coroutines to finesse control-flow, improving bulk file transfer latency.

This is running this on my Raspberry Pi 1B at freddiewoodruff.co.uk.

Out on the web there are bots probing every attack surface within the HTTP and TLS layers.
This has thrown up many curiosities and helped me harden the server.
