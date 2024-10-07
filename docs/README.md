### API Documentation

Documentation engine for detect malwares and better laboratory maldec labs

### Dependencies

For compile engine necessary : 

### Debian-based

`sudo apt install libasio-dev libyara-dev libsqlite3-dev libclamav-dev`

### Arch-based

`sudo pacman -S asio yara libpqxx sqlite`

---

### Compile and Run

```
git clone --recurse-submodules git@gitlab.com:maldec-labs/malware-analysis/Engine.git
git lfs pull
mkdir build
cd build
cmake ..
make
```

execute `./build/sources/engine`

### Overview

This API provides WebSocket-based endpoints for scanning data and searching within the system. The service is designed to handle real-time communication, ensuring efficient data transfer and processing. Below are the details for each available route, along with their respective functionalities.

---

### Endpoints

#### WebSocket Endpoints

In the file [configuration.toml](../configuration.toml), you can modify the `crow=whitelist` setting to control whether a connection is accepted based on the IP address. If an IP address is not included in the whitelist, the connection will be rejected.

#### 1. scan/yara
- **Route:** `<version>/engine/analysis/scan/yara`
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
    "match_status": 0,
    "ns": "",
    "rule": "" 
  }
  ```
  - **onclose:** 
  - **onerror:** 

- **Details:**
  - **`match_status` Values:**
    - `0`: Benign
    - `1`: Malicious
    - `2`: None


#### 2. data/metadata
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
  "creation_date": "2024-09-28",
  "entropy": -0.0,
  "mime_type": "text/plain; charset=us-ascii",
  "sha1": "755c001f4ae3c8843e5a50dd6aa2fa23893dd3ad",
  "sha224": "5fa4fb5daff0a9b069061839e5605caff0446465f82268775a226333",
  "sha256": "28cb017dfc99073aa1b47c1b30f413e3ce774c4991eb4158de50f9dbb36d8043",
  "sha384": "05542a38ee06e71f2edac136126a2df339ab79fceb399b2dc82e80c856015c9ce9105d83f58f976bdd49ca5f9ccd088d",
  "sha3_256": "350fbf3004cf9d3dea61e4a535c169b8c6d0e4e8d6db07c23b9c606fda37607f",
  "sha3_512": "e458cf38eeb666474f34773af6e9fe909426627295b50f3480fab597c596c7a31ea51e1f7512dc096df689b13ebe145e59d8aa95dd1e22b4bfa08a6bc5963ca9",
  "sha512": "2d5be0f423fee59bf2149f996e72d9f5f8df90540a7d23b68c0d0d9a9a32d2c144891ca8fe4a3c713cb6eb2991578541dad291ba623dbd7107c6a891ba00bcc8",
  "size": 11
  }
  
  ```
  - **onclose:** 
  - **onerror:** 

#### 3. capstone/x86_64 or arm_64
- **Route:** `<version>/engine/rev/disassembly/capstone/<x86_64><arm_64>`
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
  }
  ```
  - **onclose:** 
  - **onerror:** 

#### 4. debug/endpoints
- **Route:** `<version>/engine/debug/endpoints`
- **Type:** Web
- **Description:** Endpoint for generate endpoints loaded
- **Response:**
```json
{
  "/v1/engine/analysis/scan/yara": {
    "path": "/v1/engine/analysis/scan/yara",
    "type": 0,
    "connections": 0
  },
  "/v1/engine/data/metadata": {
    "path": "/v1/engine/data/metadata",
    "type": 0,
    "connections": 0
  },
  "/v1/engine/rev/disassembly/capstone/x86_64": {
    "path": "/v1/engine/rev/disassembly/capstone/x86_64",
    "type": 0,
    "connections": 0
  }
  "/v1/engine/parser/binary/elf": {
    "path": "/v1/engine/parser/binary/elf",
    "type": 0,
    "connections": 0
  },
  "/v1/engine/debug/endpoints": {
    "path": "/v1/engine/debug/endpoints",
    "type": 1
  }
  <...>
}
```
- **Details:**
  - **`type` Values:**
    - `0`: Websocket
    - `1`: Web

#### 5. scan/clamav
- **Route:** `<version>/engine/analysis/scan/clamav`
- **Type:** WebSocket
- **Description:** Endpoint for scanning Clamav rules.
- **Handlers:**
  - **onaccept:**
  - **onopen:** 
  ```json
  { "status": "ready" }
  ```
  - **onmessage:**
  ```json
  {     
   "virname":"",
   "math_status": 8
  }
  ```
  - **onclose:** 
  - **onerror:** 

- **Details:**
  - **`math_status` Values:**
    - `0`: Benign
    - `1`: Malicious
    - `2`: None
