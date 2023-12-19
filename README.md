# octo-squirrel

For study purposes only.

## Feature
### Transmission
|     | Shadowsocks | VMess |
|:----|:-----------:|:-----:|
| TCP |      ✔      |   ✔   |
| UDP |      ✔      |   ✔   |

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
        "servers":
        [
            {
                "cipher": "{cipher}",
                "password": "{password}",
                "port": "{port}",
                "protocol": "{protocol}",
                "networks":
                [
                    "{networks}"
                ]
            }
        ]
    }
    ```
    > port: which port client will be listening on

    > index: `servers[index]` will be the client config

    > protocol: "shadowsocks" | "vmess"

    > cipher: see Ciphers

    > networks: see Transmission

2. running command

    * Windows

    ```cmd
    octo-squirrel-client.exe {config.json file path}
    ```
