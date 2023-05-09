# HTTPS Web Server

Out on the web there are bots probing every attack surface within the HTTP and TLS layers.
This has thrown up many curiosities and helped me harden the server.

<details>
  
<summary>Highlights</summary>
  
* The implementations for HTTP/1.1 and TLS/1.2 are my own.
* I am using my own finite elliptic curve group implementations for TLS key-exchange and signatures.
* I have used C++20 coroutines to finesse control-flow, [improving](https://github.com/fwoodruff/https-archive) bulk file transfer latency.
* The server runs at freddiewoodruff.co.uk on my Raspberry Pi 1B.
* The C++20 executable was cross-compiled for the Raspberry Pi on an AWS EC2 instance.
</details>



<details>
<summary>Basic usage</summary>
  
```bash
git clone https://github.com/fwoodruff/HTTPS.git
git make
sudo ./codeymccodeface
```

I am updating certificates with:
  
```
sudo certbot certonly --key-type=ecdsa --cert-name=freddiewoodruff.co.uk --elliptic-curve=secp256r1 --standalone --force-renewal
```

`config.txt` is localhost.
  
`config2.txt` is my Raspberry Pi server config.
  
Config files are just a bunch of paths, with a leading `'/'` for absolute paths.
</details>

