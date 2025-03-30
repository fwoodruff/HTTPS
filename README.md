# HTTPS Web Server

Out on the web there are bots probing every attack surface within the HTTP and TLS layers.
This has thrown up many curiosities and helped me harden the server.

<details>
<summary>Highlights</summary>
  
* TLS 1.3 implementation including 0-RTT and an TLS 1.2 fallback
* Modern ChaCha20-Poly1305 and AES-GCM ciphers, with AES-CBC modes for legacy clients
* Homemade elliptic curve group implementations for TLS key-exchange and signatures
* C++20 coroutines for [improving](https://github.com/fwoodruff/https-archive) control flow specifically bulk file transfer latency and memory usage
* HTTP/1.1 range request support, enabling video streaming
* The server runs at freddiewoodruff.co.uk on my Raspberry Pi 1B.
* Includes `gcc-14` C++23 features and some homemade implementations of C++26 [features](https://en.cppreference.com/w/cpp/header/hazard_pointer).
* HTTP/2 is in the works. HPACK, HoL-blocking resistant stream-handling and full-duplex presentation layer requirements already implemented
</details>

<details>
<summary>Basic usage</summary>
  
  
Install with
```bash
git clone https://github.com/fwoodruff/HTTPS.git
cd HTTPS
```
then run with Make
```
make -j8 && ./target/codeymccodeface
```
Note, this requires GCC14 or later.

Alternatively use Docker
```bash
docker build -t server .
docker run --init --rm -p 8443:8443 -p 8080:8080 server
```


CA certificates can be renewed with:

```
sudo certbot certonly --key-type=ecdsa --cert-name=freddiewoodruff.co.uk --elliptic-curve=secp256r1 --webroot --force-renewal
```

`config.txt` is for localhost.

`live_config.txt` is my Raspberry Pi server config.

If using `live_config.txt` with docker:
```bash
docker run --init --rm -p 443:8443 -p 80:8080 -v /etc/letsencrypt:/etc/letsencrypt:ro server
```
</details>

<details>
  <summary>Benchmarks</summary>
 
| Client request                                                         | Data-rate | Transfer time |
| ---------------------------------------------------------------------- | --------- | ------------- |
| `scp freddiewoodruff.co.uk:~/doc/HTTPS20/webpages/assets/carina.png .` | 3.0MB/s   | 41s           |
| `wget https://freddiewoodruff.co.uk/assets/carina.png`                 | 702KB/s   | 3m 3s         |
</details>
