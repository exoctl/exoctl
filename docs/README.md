## 📄 **API Documentation**  
### Malware Detection Engine Skull

This API provides WebSocket-based endpoints for scanning data, binary analysis, metadata extraction, and disassembly. It ensures real-time communication with high efficiency and low latency.  

---

### **Requirements**  
#### **Debian-based**  
```bash
sudo apt install libasio-dev libyara-dev libsqlite3-dev libclamav-dev
```

#### **Arch-based**  
```bash
sudo pacman -S asio yara libpqxx sqlite clamav
```

---

### **How to Build and Run**  
```bash
git clone --recurse-submodules git@github.com:maldeclabs/engine.git 
git lfs pull
mkdir build
cd build
cmake ..
make
./build/sources/engine
```

---

## **Endpoints Overview**  

### 📡 **Analysis Group**  
#### **Full Scan**  
- **Route:** `<version>/engine/analysis/scan`  
- **Description:** Executes a full scan using YARA and ClamAV.  

**Received Message Example:**  
```json
{ "status": "ready" }
```

**Sent Message Example:**  
```json
{
  "yara": 
  { 
    "ns": "", 
    "rule": "", 
    "match_status": 0 
  },
  "av": 
  { 
    "clamav": 
    { 
      "virname": "", 
      "match_status": 0 
      }
  }
}
```

---

#### **YARA Scan**  
- **Route:** `<version>/engine/analysis/scan/yara`  
- **Description:** Runs a scan with YARA rules.  

**Match Status:**  
- `0`: Benign  
- `1`: Malicious  
- `2`: No Match  

---

#### **ClamAV Scan**  
- **Route:** `<version>/engine/analysis/scan/av/clamav`  
- **Description:** Executes a scan using ClamAV antivirus.  

**Example Response:**  
```json
{ "virname": "", "match_status": 1 }
```

---

### 🛠 **Metadata Extraction**  
#### **File Metadata**  
- **Route:** `<version>/engine/data/metadata`  
- **Description:** Returns file information like hashes and MIME type.  

**Example Response:**  
```json
{
  "mime_type":"application/x-empty; charset=binary",
  "sha256":"e3b0c44298fc1c149afbf4...",
  "sha1":"da39a3ee5e6b4b0d3255bfef...",
  "sha512":"cf83e1357eefb8bdf15428...",
  "sha224":"d14a028c2a3a2bc9476102...",
  "sha384":"38b060a751ac96384cd932...",
  "sha3_256":"a7ffc6f8bf1ed76651c14756...",
  "sha3_512":"a69f73cca23a9ac5c8b567dc...",
  "size":0,
  "creation_date":"2024-10-22",
  "entropy":-0.0
}
```

---

### 🔍 **Binary Disassembly and Analysis**  
#### **Disassembly with Capstone**  
- **Route:** `<version>/engine/rev/disassembly/capstone/<x64|arm64>`  
- **Description:** Generates disassembly for x86_64 or ARM64 binaries.  

**Example Response:**  
```json
{
  "arch": "x86_64",
  "disassembly": [
    { 
      "address": "0x782f...", 
      "mnemonic": "call", 
      "operands": "[rip + 0xa00f]", 
      "size": 6 
    },
    { 
      "address": "0x782f...", 
      "mnemonic": "ret", 
      "size": 1 
    }
  ]
}
```

---

#### **ELF Parser**  
- **Route:** `<version>/engine/parser/binary/elf`  
- **Description:** Parses ELF files and returns their headers.  

**Example Response:**  
```json
{
  "header": {
    "identity_version": "1",
    "entrypoint": "6d30",
    "program_headers_offset": "40",
    "numberof_sections": "1f"
  }

  ...
}
```

#### **MACHO Parser**  
- **Route:** `<version>/engine/parser/binary/macho`  
- **Description:** Parses MACHO files and returns their headers.  

**Example Response:**  
```json
{
  "code_signature": {
    "command": "CODE_SIGNATURE",
    "command_offset": 2024,
    "command_size": 16,
    "data_hash": 8289885841418134514,
    "data_offset": 34128,
    "data_size": 5456
  },
  "dyld_info": {
    "command": "DYLD_INFO_ONLY",
    "command_offset": 1440,
    "command_size": 48,
    "data_hash": 15608440747057431502
  },
  "dylinker": {
    "command": "LOAD_DYLINKER",
    "command_offset": 1592,
    "command_size": 32,
    "data_hash": 1879844007031036313,
    "name": "/usr/lib/dyld"
  }

  ...
}

```
---

#### **PE Parser**  
- **Route:** `<version>/engine/parser/binary/pe`  
- **Description:** Parses PE files and returns their headers.  

**Example Response:**  
```json
{
  "data_directories": [
    {
      "RVA": 0,
      "size": 0,
      "type": "EXPORT_TABLE"
    },
    {
      "RVA": 0,
      "size": 0,
      "type": "CERTIFICATE_TABLE"
    },
    {
      "RVA": 303104,
      "section": ".reloc",
      "size": 6940,
      "type": "BASE_RELOCATION_TABLE"
    },
    {
      "RVA": 145768,
      "section": ".text",
      "size": 56,
      "type": "DEBUG_DIR"
    },
    {
      "RVA": 0,
      "size": 0,
      "type": "ARCHITECTURE"
    },
    {
      "RVA": 0,
      "size": 0,
      "type": "GLOBAL_PTR"
    },
    {
      "RVA": 0,
      "size": 0,
      "type": "TLS_TABLE"
    },
    {
      "RVA": 113552,
      "section": ".text",
      "size": 64,
      "type": "LOAD_CONFIG_TABLE"
    }
  ]
  ...
}
```

---

#### **DEX Parser**  
- **Route:** `<version>/engine/parser/binary/dex`  
- **Description:** Parses DEX files and returns their headers.  

**Example Response:**  
```json
{
  "classes": [
    {
      "fullname": "Lcom/rafaelkhan/android/download/DownloadMain$Downloader;",
      "index": 0,
      "access_flags": [],
      "fields": [
        {
          "access_flags": ["PRIVATE"],
          "index": 2,
          "is_static": false,
          "name": "bout",
          "type": {
            "type": "CLASS",
            "value": "Ljava/io/BufferedOutputStream;"
          }
        },
        {
          "access_flags": ["PRIVATE"],
          "index": 3,
          "is_static": false,
          "name": "fileName",
          "type": {
            "type": "CLASS",
            "value": "Ljava/lang/String;"
          }
        },
        {
          "access_flags": ["PRIVATE"],
          "index": 4,
          "is_static": false,
          "name": "fileSize",
          "type": {
            "type": "PRIMITIVE",
            "value": "int"
          }
        },
        {
          "access_flags": ["PRIVATE"],
          "index": 5,
          "is_static": false,
          "name": "http",
          "type": {
            "type": "CLASS",
            "value": "Ljava/net/HttpURLConnection;"
          }
        },
        {
          "access_flags": ["PRIVATE"],
          "index": 6,
          "is_static": false,
          "name": "in",
          "type": {
            "type": "CLASS",
            "value": "Ljava/io/BufferedInputStream;"
          }
        },
        {
          "access_flags": ["FINAL", "SYNTHETIC"],
          "index": 7,
          "is_static": false,
          "name": "this$0",
          "type": {
            "type": "CLASS",
            "value": "Lcom/rafaelkhan/android/download/DownloadMain;"
          }
        },
        {
          "access_flags": ["PRIVATE"],
          "index": 8,
          "is_static": false,
          "name": "url",
          "type": {
            "type": "CLASS",
            "value": "Ljava/net/URL;"
          }
        }
      ],
      "methods": [
        {
          "access_flags": ["PRIVATE", "CONSTRUCTOR"],
          "index": 15,
          "is_virtual": false,
          "name": "<init>",
          "code_offset": 2716,
          "prototype": {
            "parameters": [
              {
                "type": "CLASS",
                "value": "Lcom/rafaelkhan/android/download/DownloadMain;"
              }
            ]
          }
        }
      ]
    }
  ]
  ...
}

```

## **WebSocket Interaction Guide**  
1. **Connect:** Establish a connection with the endpoint.  
2. **onopen:** API will respond with `{"status":"connected","message":"Connected successfully","code":200}`.  
3. **onmessage:** Send a message for the desired analysis.  
4. **onclose:** The connection will close after processing.  
5. **onerror:** Errors will trigger an appropriate response.  

---

## **Final Notes**  
- Use **`<version>`** to indicate the desired API version (e.g., `/v1/engine/...`).  
- This API is optimized for real-time processing, ensuring fast and efficient sample analysis.  

---

This concise structure ensures easy navigation and practical examples, helping developers integrate the API seamlessly.
