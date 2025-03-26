local config <const> = Configuration:new()
local logging <const> = Logging:new()
local server = require("plugins.addons.mcp.server")

-- ========================
-- Setup and Load Configuration
-- ========================

config:setup("plugins/addons/mcp/mcp.conf")
config:load()

logging:setup(config)
logging:load()

server:setup(config, logging)
server:run()