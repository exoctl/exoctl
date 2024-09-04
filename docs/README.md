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

#### 1. Scan Yara
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