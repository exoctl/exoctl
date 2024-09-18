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

### SDKs

#### Signatures



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
  {"is_malicius":0,"yara_rule":"none"}
  ```
  - **onclose:** 
  - **onerror:** 

- **Details:**
  - **`is_malicious` Values:**
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
   "creation_date":"2024-09-04",
   "entropy":3.9959065984842446,
   "mime_type":"text/x-shellscript; charset=us-ascii",
   "sha256":"0ca6e039ddb80b48f1b4a79dd47b90d5ec41337597f6d584603d63314a5a982c",
   "size":36
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