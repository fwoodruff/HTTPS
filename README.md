# HTTPS Web Server

Out on the web there are bots probing every attack surface within the HTTP and TLS layers.
This has thrown up many curiosities and helped me harden the server.

<details>
<summary>Highlights</summary>
  
* Full [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) implementation including 0-RTT, with modern ChaCha20-Poly1305 and AES-GCM AEAD ciphers
* Full [HTTP/2](https://datatracker.ietf.org/doc/html/rfc9113) implementation
* Homemade elliptic curve group implementations for TLS key-exchange and signatures
* HTTP/1.1 and TLS 1.2 fallbacks with both modern and legacy ciphers
* C++20 coroutines for [improving](https://github.com/fwoodruff/https-archive) control flow particularly around bulk file transfer latency
* Buffered and skippable video streaming supported with HTTP range requests
* Supports [HTTP-01](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3) ACME challenges
  * SSL certificates are renewed automatically with no server downtime
* [HPACK](https://datatracker.ietf.org/doc/html/rfc7541)
  * Huffman compression for strings - these can be toggled off for secrets
  * Dynamic indexing of HTTP headers, for requests on the same TCP connection
* Fixed size data frames
  * Avoids fragmentation between ethernet packets
  * Ensures TLS record size patterns do not reveal data contents
* Handles multiple concurrent requests on the same TCP connection
* Consumes frames eagerly when streaming to manage back-pressure in real-time
* The server runs at https://freddiewoodruff.co.uk on a Raspberry Pi 1 Model B.
* Homemade event and task manager
  - lock-free task executor with a fixed-size threadpool
  - `poll()`-based event reactor
  - [Rust port](https://github.com/fwoodruff/async_io) of this component
* Includes `gcc-14` C++23 features and some homemade implementations of C++26 [features](https://en.cppreference.com/w/cpp/header/hazard_pointer) for achieving lock-freedom

</details>

<details>
<summary>Usage</summary>
  
  
Install with
```bash
git clone https://github.com/fwoodruff/HTTPS.git
cd HTTPS
```
then run with Make
```
make -j$(nproc) && ./target/codeymccodeface
```
Note, this requires GCC 14 or later.

Alternatively use Docker
```bash
docker build -t server .
docker run --init --rm -p 8443:8443 -p 8080:8080 server
```


CA certificates can renewed with:
```bash
sudo certbot certonly \
  --webroot \
  -w /home/freddiewoodruff/doc/HTTPS23/resources/webpages/freddiewoodruff.co.uk \
  --key-type ecdsa \
  --elliptic-curve secp256r1 \
  --cert-name freddiewoodruff.co.uk \
  -d freddiewoodruff.co.uk \
  -d www.freddiewoodruff.co.uk \
  --force-renewal
```
Set up a cronjob for renewal with `sudo crontab -e`
```
0 */12 * * * certbot renew --quiet
```

`config.txt` is for localhost.

`live_config.txt` is my Raspberry Pi server config.

</details>

<details>
  <summary>Benchmarks</summary>
 
| Client request                                                         | Data-rate | Transfer time |
| ---------------------------------------------------------------------- | --------- | ------------- |
| `scp freddiewoodruff.co.uk:~/doc/HTTPS20/webpages/assets/carina.png .` | 3.0MB/s   | 41s           |
| `wget https://freddiewoodruff.co.uk/assets/carina.png`                 | 702KB/s   | 3m 3s         |
</details>


<details>
  <summary>Targeting</summary>

Compiling C++23 for a Raspberry Pi 1B mixes old with new.
`Dockerfile.armv6` downloads a cross-compiler and builds the ARMv6 binary. Run as follows:
```bash
mkdir -p target
docker build -t containerymccontainerface -f Dockerfile.armv6 .
c_id=$(docker create containerymccontainerface)
docker cp $c_id:/target/codeymccodeface ./target/codeymccodeface.armv6
docker rm $c_id
```
</details>

