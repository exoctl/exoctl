<p align="center">
  <img src="assets/banner.png" width="250" alt="exoctl Engine Banner">
</p>

<h1 align="center">
  <span style="color: #EF4444;">Threat</span><span style="color: #F8F8F2;">DB</span>
</h1>

<h4 align="center">Advanced malware analysis engine with plugin support. Extend functionality to automate your analysis workflows and solve repetitive tasks efficiently.</h4>

<p align="center">
  <a href="https://github.com/exoctl/exoctl/actions/workflows/docker-image.yml?query=branch%3Amain">
    <img src="https://github.com/exoctl/exoctl/actions/workflows/docker-image.yml/badge.svg?branch=main" alt="Docker Image CI - Main">
  </a>
  <a href="https://github.com/exoctl/exoctl/actions/workflows/docker-image.yml?query=branch%3Adev">
    <img src="https://github.com/exoctl/exoctl/actions/workflows/docker-image.yml/badge.svg?branch=dev" alt="Docker Image CI - Dev">
  </a>
</p>

## Description

A malware analysis engine with support for plugins in Lua. Designed to automate analysis workflows, handle repetitive tasks, and provide flexible inspection of file formats.

> [!NOTE]  
> I'm working on documentation about the engine and everything it can do.

## Setting Up / Building

### Clone the Repository

```sh
git clone --recurse-submodules -j8 git@github.com:exoctl/exoctl.git
```

## Build using cmake 

Install libraries 

```sh
sudo apt update && apt install -y build-essential g++-14 gcc  libyara-dev  libclamav-dev  binutils  git  libsqlite3-dev libmysqlclient-dev  libpq-dev  clamav  libpqxx  libasio-dev
```

Build

```sh
mkdir -p build
cd build
cmake ..
make
```

Run engine `EXOCTLDIR=./sources/app/  ./build/sources/appexoctl`

#### Using Dockerfile

```
sudo docker build -t engine .
sudo docker run --name engine -p 8081:8081 engine
```


## Plugin Examples

### Configuration

```lua
local config = Configuration:new()
config:setup("example.conf")
config:load()

local name = config:get("plugin.name")
```

---

### Logging

```lua
local logging = Logging:new()
logging:setup(config)
logging:load()

logging:info("Engine initialized")
```

---

### YARA Integration

```lua
local yara = Yara:new()

yara:set_rule_buff('rule Test { condition: true }', 'Namespace_Test')
yara:load_rules()

yara:scan_bytes("buffer", function(message, data)
    if message == YaraFlags.RuleMatching then
        _engine.logging:warn("Matched: " .. data.identifier)
    end
end, YaraFlags.FAST_MODE)
```

---

### Web Endpoint

```lua
Web.new(server, "/scan", function (req)
    return Response.new(200, "OK")
end)
```

---

### JSON Handling

```lua
local json = Json:new()
json:add("engine", "exoctl")
print(json:tostring())
```

---

## Default Endpoints 

### Get Analysis Records

Endpoint:  
GET `/engine/v1/analysis/records`

Description:  
Fetch all analysis records from the engine.

Example Request:

`curl -X GET http://127.0.0.1:8081/engine/v1/analysis/records | jq`

Example Response:
```json
{
  "records": [
    {
      "id": 1,
      "file_name": "malware.exe",
      "file_type": "application/vnd.microsoft.portable-executable; charset=binary",
      "sha256": "b87278604e86a5ea55f04809e5e253c68cc6a17335dda5ef3f418c04536d22bc",
      "sha1": "425fb790d10e32b2e6e7c52d72e310b713f622ba",
      "sha512": "a1ae73161052e2ea62aabfd8e129d071fc0f6b293a0efbde3321f071de8c5da94b5a71d6f982d00fef50896f37092b9129003ba89f53b63f8b34a8eed9514c5d",
      "sha224": "2685702f887de14ddfcd4167beb8fa45c93ae0e7ecb05c7080691c4f",
      "sha384": "e0938e7e140788665a1222bc1216d8528be0d10df484f0dff1e075cafcdea1b56a2c58e984b4497ae7c78d780c5f504c",
      "sha3_256": "8622d6916fb9c06fa642e52836b69b7f6a971d61d2482809c8e6d22d13a94eab",
      "sha3_512": "633e4debd4700e154f67fb60a85326578b73bb39358cb9e64c183730edd4aa88e4b425df55e621207ce22ba4701d34f0206fc208d1e9d69099b6e29c0cbb3120",
      "file_size": 49152,
      "file_entropy": 5.562467278848947,
      "creation_date": "2025-08-27",
      "last_update_date": "2025-08-29",
      "file_path": "./files",
      "is_malicious": true,
      "is_packed": false,
      "family_id": 1,
      "description": "File detected as malicious",
      "owner": "127.0.0.1",
      "tlsh": "D8233B003BE8C12BF2BE4F74A9F22145867AF6673603D55E1CC4419B5A13FC696826FE",
      "family": {
        "id": 1,
        "name": "AsyncRAT",
        "description": "Malware Trojan"
      },
      "tags": [
        {
          "id": 2,
          "name": "malware",
          "description": "trojan"
        }
      ]
    }
  ],
  "code": 200,
  "status": "connected"
}
```
### Get Tags

Endpoint:  
GET `/engine/v1/tags`

Example Response:
```json
{
  "tags": [
    {
      "id": 1,
      "name": "packed",
      "description": "File is packed"
    },
    {
      "id": 2,
      "name": "malware",
      "description": "trojan"
    }
  ],
  "code": 200,
  "status": "connected"
}
```

### Get Families

Endpoint:  
GET `/engine/v1/families`

Example Response:
```json
{
  "families": [
    {
      "id": 1,
      "name": "AsyncRAT",
      "description": "Malware Trojan"
    },
    {
      "id": 2,
      "name": "RedLine",
      "description": "Stealer"
    }
  ],
  "code": 200,
  "status": "connected"
}
```


### Create a Tag

Endpoint:  
POST `/engine/v1/tags/create`

Request Body:
```json
{
  "name": "ransomware",
  "description": "Files related to ransomware"
}
```
Example Response:
```json
{
  "tag": {
    "id": 3,
    "name": "ransomware",
    "description": "Files related to ransomware"
  },
  "code": 201,
  "status": "created"
}
```
### Create a Family

Endpoint:  
POST `/engine/v1/families/create`

Request Body:
```json
{
  "name": "Emotet",
  "description": "Banking Trojan"
}
```

Example Response:
```json
{
  "family": {
    "id": 3,
    "name": "Emotet",
    "description": "Banking Trojan"
  },
  "code": 201,
  "status": "created"
}
```


## Associated Projects

You can interact with your engine through the **exoctl-cli** 

- **[exoctl-cli](https://github.com/exoctl/exoctl-cli)**: A command-line interface to seamlessly communicate with your engine and manage interactions with your system.
- **[threat-db](https://github.com/exoctl/threatdb)**: Graphical interface running on a web server with the intention of using the engine to be a malware manager

Feel free to check out these repositories for more information and contributions.