# HTTPS20
HTTPS web server with coroutines

This is a secure web server. The code is C++20. The implementations for HTTP/1.1 and TLS/1.2 are my own.
I am using my own elliptic curve implementations for key-exchange and signatures.

In my C++17 HTTPS web server, serving large files introduced a DoS opportunity; files were being read into memory before being passed to the TLS state machine.
Coroutines solve this problem and improve separation of concerns.

I am running this on my Raspberry Pi 1B at freddiewoodruff.co.uk. I am using my own elliptic curve implementations for key-exchange and signatures.

Out on the web there seem to be bots probing every attack surface within the HTTP and TLS layers. This has thrown up many curiosities and helped me harden the server.
