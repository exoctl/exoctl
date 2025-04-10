-- ========================
-- Initialization and Configuration
-- ========================

local config <const> = Configuration:new()
local logging <const> = Logging:new()
local server <const> = require("plugins.threat.scan.mserver"):new()
local scan <const> = require("plugins.threat.scan.scan")
local api <const> = {
    scan = require("plugins.threat.scan.api.scan"):new()
}

local ui <const> = require("plugins.threat.scan.ui.ui"):new()

-- ========================
-- Setup and Load Configuration
-- ========================

print(_engine.version.code)
config:setup("plugins/threat/scan/config.conf")
config:load()

logging:setup(config)
logging:load()

server:setup(config, logging)
server:load()

scan:setup(config, logging)
scan:load()

-- APis
api.scan:setup(server, scan)
api.scan:load()

-- UI
ui:setup(config, logging, server)
ui:load()

-- tick
-- local time <const> = config:get("yaragate.rules.destroy.server.tick_time")
-- server:create_tick(60 * 1000, function()
--     logging:debug("Calling tick for reset " .. tostring(yara.reset_time))
--     myara.reset_time = yara.reset_time - 1
--     if (myara.reset_time == 0) then
--         myara:reset_rules()
--         myara.reset_time = time
--     end
-- end)

server:run() -- start server wich service