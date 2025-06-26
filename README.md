<p align="center"><img src="assets/banner.png" width=250 alt="exoctl Engine Banner"></p>

<h4 align="center">Advanced malware analysis engine with plugin support. Extend functionality to automate your analysis workflows and solve repetitive tasks efficiently.</h4>

<p align="center">
  <a href="https://exoctl.com">
    <img src="https://img.shields.io/badge/Website-Live-green?style=for-the-badge&logo=google-chrome" alt="Official Website">
  </a>
  <a href="https://maldecs-organization.gitbook.io/maldeclabs-docs">
    <img src="https://img.shields.io/badge/Documentation-Read-blue?style=for-the-badge&logo=gitbook" alt="Documentation">
  </a>
</p>


## Description

A malware analysis engine with support for plugins in Lua. Designed to automate analysis workflows, handle repetitive tasks, and provide flexible inspection of file formats.

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

yara:load_rules(function ()
    yara:set_rule_buff('rule Test { condition: true }', 'Test')
end)

yara:scan_fast_bytes("buffer", function(result)
    if result.match_status == 1 then
        logging:warn("Matched: " .. result.rule)
    end
end)
```

---

### Web Endpoint

```lua
Web.new(server, "/scan", function (req)
    return Response.new(200, "OK")
end, HTTPMethod.Post)
```

---

### JSON Handling

```lua
local json = Json:new()
json:add("engine", "exoctl")
print(json:to_string())
```

---

> [!NOTE]  
> For complete examples, visit our [documentation/examples](https://maldecs-organization.gitbook.io/maldeclabs-docs/developer-guide/plugins-lua/examples)

## Associated Projects

You can interact with your engine through the **exoctl-cli** and explore various plugins developed by **my** and the community via the **exoctl-plugins** repository.

- **[exoctl-cli](https://github.com/exoctl/exoctl-cli)**: A command-line interface to seamlessly communicate with your engine and manage interactions with your system.
- **[exoctl-plugins](https://github.com/exoctl/exoctl-plugins)**: A collection of plugins created by **my** and the open-source community, extending the functionality of the engine with new features and integrations.

Feel free to check out these repositories for more information and contributions.

## Setting Up / Building

To develop the project and perform the build, the following steps are necessary verify [documentation/build](https://maldecs-organization.gitbook.io/maldeclabs-docs/getting-started/build)