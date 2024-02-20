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
  
  
Install with
```bash
git clone https://github.com/fwoodruff/HTTPS.git
cd HTTPS
```
then run with either Make
```
make -j8 && ./target/codeymccodeface
```
or Docker
```bash
docker compose up
```

Every 60 days, CA certificates are updated with:
  
```
sudo certbot certonly --key-type=ecdsa --cert-name=freddiewoodruff.co.uk --elliptic-curve=secp256r1 --webroot --force-renewal
```

`config.txt` is for localhost.

`config_live.txt` is my Raspberry Pi server config.
</details>

<details>
  <summary>Benchmarks</summary>
 
| Client request                                                         | Data-rate | Transfer time |
| ---------------------------------------------------------------------- | --------- | ------------- |
| `scp freddiewoodruff.co.uk:~/doc/HTTPS20/webpages/assets/carina.png .` | 3.0MB/s   | 41s           |
| `wget https://freddiewoodruff.co.uk/assets/carina.png`                 | 702KB/s   | 3m 3s         |
</details>
