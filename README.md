<p align="center"><img src="assets/banner.png" width=600 alt="Infinity Engine Banner"></p>

<h4 align="center">Advanced malware analysis engine with plugin support. Extend functionality to automate your analysis workflows and solve repetitive tasks efficiently.</h4>

<p align="center">
  <a href="https://maldec.io/infinity-engine">
    <img src="https://img.shields.io/badge/Website-Live-green?style=for-the-badge&logo=google-chrome" alt="Official Website">
  </a>
  <a href="https://maldecs-organization.gitbook.io/maldeclabs-docs">
    <img src="https://img.shields.io/badge/Documentation-Read-blue?style=for-the-badge&logo=gitbook" alt="Documentation">
  </a>
  <a href="https://discord.gg/BUkcdta9b7">
    <img src="https://img.shields.io/discord/1121113706621833236?style=for-the-badge&color=7289DA&logo=discord&label=Join%20Our%20Discord" alt="Discord Community">
  </a>
  <a href="https://opencollective.com/maldec">
    <img src="https://img.shields.io/badge/Support-Our_Work-orange?style=for-the-badge&logo=opencollective" alt="Support Maldec">
  </a>
</p>


## Description

A reverse engineering and malware analysis engine with support for plugins in Lua. Designed to automate analysis workflows, handle repetitive tasks, and provide flexible inspection of file formats.

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
json:add("engine", "maldeclabs")
print(json:to_string())
```

---

> [!NOTE]  
> For complete examples, visit our [documentation/examples](https://maldecs-organization.gitbook.io/maldeclabs-docs/developer-guide/plugins-lua/examples)

## Associated Projects

You can interact with your engine through the **infinity-cli** and explore various plugins developed by **maldeclabs** and the community via the **infinity-plugins** repository.

- **[infinity-cli](https://github.com/maldeclabs/infinity-cli)**: A command-line interface to seamlessly communicate with your engine and manage interactions with your system.
- **[infinity-plugins](https://github.com/maldeclabs/infinity-plugins)**: A collection of plugins created by **maldeclabs** and the open-source community, extending the functionality of the engine with new features and integrations.

Feel free to check out these repositories for more information and contributions.

## Setting Up / Building

To develop the project and perform the build, the following steps are necessary verify [documentation/build]()