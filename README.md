# octo-squirrel

A network tool for improved privacy and security.

## Feature
### Local
- socks5

### Transport
|               | Shadowsocks | VMess | Trojan |
|:--------------|:-----------:|:-----:|:------:|
| tcp           |      ✔      |   ✔   |   ✔    |
| udp           |      ✔      |   ✔   |   ✔    |

### Ciphers
|                         | Shadowsocks |  VMess  |
|:------------------------|:-----------:|:-------:|
| aes-128-gcm             |     `C`     |   `C`   |
| aes-256-gcm             |     `C`     |         |
| chacha20-poly1305       |     `C`     |   `C`   |
| 2022-blake3-aes-128-gcm |     `C`     |         |
| 2022-blake3-aes-256-gcm |     `C`     |         |

`C` for client

## How to run
1. put config.json file before running

    ```json
    {
        "port": 0,
        "index": 0,
        "servers": [
            {
                "cipher": "{cipher}",
                "password": "{password}",
                "port": "{port}",
                "protocol": "{protocol}",
                "networks": [
                    "{networks}"
                ]
            }
        ],
        "ssl": {
            "certificateFile": "/path/to/certificate.crt",
            "serverName": ""
        }
    }
    ```

    > port: which port client will be listening on

    > index: `servers[index]` will be the client config

    > protocol: "shadowsocks" | "vmess"

    > cipher: see Ciphers

    > networks: see Transmission

    > `ssl`: (OPTIONAL) SSL specific configurations

    > > `certificateFile`: certificate file

    > > `serverName`: the Server Name Indication field in the SSL handshake.

2. running command

    * Windows

    ```cmd
    octo-squirrel-client.exe 'config.json file path'
    ```
