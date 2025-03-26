local config <const> = Configuration:new()
local logging <const> = Logging:new()
local server = require("plugins.sdks.mcp.server")
local jsonrpc = require("plugins.sdks.mcp.jsonrpc")

-- ========================
-- Setup and Load Configuration
-- ========================

config:setup("plugins/sdks/mcp/mcp.conf")
config:load()

logging:setup(config)
logging:load()

local json = jsonrpc:new()

json:register_method("sum", function(params)
    return params:get("a") + params:get("b")
end)

json:register_method("echo", function(params)
    return params:get("message")
end)

local params = Json:new()
params:add("a", 10)
params:add("message", "ola mundo")

local test = Json:new()
test:add(42);
test:add("Hello, world!");
test:add(true);


local request = Json:new()
request:add("jsonrpc", "2.0")
request:add("method", "echo")
request:add("params", params)
request:add("id", 1)
request:add("test", test)

print(request:to_string())

local response = json:handle_request(request)
print(response:get("result")) -- {"jsonrpc":"2.0","result":30,"id":1}

-- server:setup(config, logging)
-- server:run()
