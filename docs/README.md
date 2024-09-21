### API Documentation

Documentation engine for detect malwares and better laboratory maldec labs

### Dependencies

For compile engine necessary : 

### Debian-based

`sudo apt install libasio-dev libyara-dev libpqxx-dev libsqlite3-dev`

### Arch-based

`sudo pacman -S asio yara libpqxx sqlite`

---

### Overview

This API provides WebSocket-based endpoints for scanning data and searching within the system. The service is designed to handle real-time communication, ensuring efficient data transfer and processing. Below are the details for each available route, along with their respective functionalities.

---

### Endpoints

#### WebSocket Endpoints

In the file [configuration.toml](../configuration.toml), you can modify the `crow=whitelist` setting to control whether a connection is accepted based on the IP address. If an IP address is not included in the whitelist, the connection will be rejected.

#### 1. scan_yara
- **Route:** `<version>/engine/analysis/scan_yara`
- **Type:** WebSocket
- **Description:** Endpoint for scanning Yara rules.
- **Handlers:**
  - **onaccept:**
  - **onopen:** 
  ```json
  { "status": "ready" }
  ```
  - **onmessage:**
  ```json
  {     
    "yara_match_status": 0,
    "yara_namespace": "",
    "yara_rule": "" 
  }
  ```
  - **onclose:** 
  - **onerror:** 

- **Details:**
  - **`yara_match_status` Values:**
    - `0`: Benign
    - `1`: Malicious
    - `2`: None


#### 2. metadata
- **Route:** `<version>/engine/data/metadata`
- **Type:** WebSocket
- **Description:** Endpoint for collect medatada.
- **Handlers:**
  - **onaccept:**
  - **onopen:** 
  ```json
  { "status": "ready" }
  ```
  - **onmessage:**
  ```json
  {
    "creation_date": "2024-09-20",
    "entropy": 0,
    "mime_type": "application/octet-stream; charset=binary",
    "sha1": "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
    "sha224": "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
    "sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "sha3-256": "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
    "sha3-512": "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a",
    "sha384": "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
    "sha512": "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
    "size": 1
  }
  ```
  - **onclose:** 
  - **onerror:** 

#### 3. x86_64 or arm_64
- **Route:** `<version>/engine/rev/capstone/disassembly/<x86_64><arm_64>`
- **Type:** WebSocket
- **Description:** Endpoint for generate disassembly x86_64 or arm_64
- **Handlers:**
  - **onaccept:**
  - **onopen:** 
  ```json
  { "status": "ready" }
  ```
  - **onmessage:**
  ```json
  {
    "arch": "arch",
    "mode": "mode",
    "disassembly": [
        [
            {
                "address": "0x782f796c626d6573",
                "bytes": "ff 15 f a0 0 0",
                "id": 62,
                "mnemonic": "call",
                "operands": "qword ptr [rip + 0xa00f]",
                "size": 6
            },
            {
                "address": "0x782f796c626d6579",
                "bytes": "c3",
                "id": 633,
                "mnemonic": "ret",
                "operands": "",
                "size": 1
            }
        ]
    ]
  }
  ```
  - **onclose:** 
  - **onerror:** 

#### 4. endpoints
- **Route:** `<version>/engine/debug/endpoints`
- **Type:** Web
- **Description:** Endpoint for generate endpoints loaded
- **Response:**
```json
[
  {
    "connections": 0,
    "path": "/v1/engine/analysis/scan_yara",
    "type": 0
  },
  {
    "connections": 0,
    "path": "/v1/engine/data/metadata",
    "type": 0
  },
  {
    "path": "/v1/engine/debug/endpoints",
    "type": 1
  }

  <...>
]
```
- **Details:**
  - **`type` Values:**
    - `0`: Websocket
    - `1`: Web