# octo-squirrel

A network tool for improved privacy and security.

## Feature

### Local

- socks5
- http
- https

### Transport

Only support IPv4 at this time.

| Local-Peer | Client-Server | Shadowsocks | VMess | Trojan |
|:----------:|:-------------:|:-----------:|:-----:|:------:|
|   `tcp`    |     `tcp`     |      ✔      |   ✔   |   ✔    |
|   `tcp`    |     `tls`     |      ✔      |   ✔   |   ✔    |
|   `tcp`    |     `ws`      |      ✔      |   ✔   |   ✔    |
|   `tcp`    |     `wss`     |      ✔      |   ✔   |   ✔    |
|   `udp`    |     `udp`     |      ✔      |       |        |
|   `udp`    |     `tcp`     |             |   ✔   |        |
|   `udp`    |     `tls`     |             |   ✔   |   ✔    |
|   `udp`    |     `ws`      |             |   ✔   |        |
|   `udp`    |     `wss`     |             |   ✔   |   ✔    |

### Ciphers

|                               | Shadowsocks |  VMess  |
|:------------------------------|:-----------:|:-------:|
| aes-128-gcm                   |   `C` `S`   | `C` `S` |
| aes-256-gcm                   |   `C` `S`   |         |
| chacha20-poly1305             |   `C` `S`   | `C` `S` |
| 2022-blake3-aes-128-gcm       |   `C` `S`   |         |
| 2022-blake3-aes-256-gcm       |   `C` `S`   |         |
| 2022-blake3-chacha20-poly1305 |   `C` `S`   |         |

`C` for client `S` for server

## How to run

### Client

1. put config.json file before running

    ```json
    {
        "port": 0,
        "index": 0,
        "mode": "{mode}",
        "servers": [
            {
                "cipher": "{cipher}",
                "password": "{password}",
                "port": "{port}",
                "protocol": "{protocol}"
            }
        ],
        "ssl": {
            "certificateFile": "/path/to/certificate.crt",
            "serverName": ""
        },
        "ws": {
            "header": {
                "Host": "example.com"
            },
            "path": "/ws"
        }
    }
    ```

   > port: which port client will be listening on

   > index: `servers[index]` will be the client config

   > mode: (OPTIONAL) client listening mode, options are "tcp"(default), "udp", "tcp_and_udp"

   > protocol: "shadowsocks" | "vmess" | "trojan"

   > cipher: see Ciphers

   > ssl: (OPTIONAL) SSL specific configurations

   > > certificateFile: certificate file

   > > serverName: the Server Name Indication field in the SSL handshake.

   > ws: (OPTIONAL) WebSocket specific configurations

   > > header: the header to be sent in HTTP request, should be key-value pairs in clear-text string format

   > > path: the HTTP path for the websocket request

2. running command

    * Windows

    ```cmd
    octo-squirrel-client.exe {config path}
    ```

### Server

1. put config.json file before running

    ```json
    [
        {
            "cipher": "{cipher}",
            "password": "{password}",
            "port": "{port}",
            "protocol": "{protocol}",
            "ws": {
                "path": "/ws"
            },
            "ssl": {
                "certificateFile": "/path/to/certificate.crt",
                "keyFile": "/path/to/key.crt",
                "serverName": ""
            }
        }
    ]
    ```

2. running command

    * Linux

    ```bash
    ./octo-squirrel-server '{config path}'
    ```