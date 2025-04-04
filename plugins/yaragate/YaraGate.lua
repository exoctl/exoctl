-- ========================
-- Initialization and Configuration
-- ========================

local config <const> = Configuration:new()
local logging <const> = Logging:new()
local server <const> = require("plugins.yaragate.Server"):new()
local api <const> = {
    get_rules = require("plugins.yaragate.api.GetRules"):new(),
    scan = require("plugins.yaragate.api.Scan"):new(),
    disable_rules = require("plugins.yaragate.api.DisableRules"):new(),
    enable_rules = require("plugins.yaragate.api.EnableRules"):new(),
    load_rule = require("plugins.yaragate.api.LoadRules"):new(),
    get_reset_rules = require("plugins.yaragate.api.GetResetRules"):new()
}

local yara <const> = require("plugins.yaragate.MYara"):new()
local ui <const> = require("plugins.yaragate.ui.Ui"):new()


-- ========================
-- Setup and Load Configuration
-- ========================

config:setup("plugins/yaragate/config.conf")
config:load()

logging:setup(config)
logging:load()

yara:setup(config, logging)
yara:load()

server:setup(config, logging)

-- APis

api.get_rules:setup(server, yara)
api.get_rules:load()

api.enable_rules:setup(server, yara)
api.enable_rules:load()

api.get_reset_rules:setup(server, yara)
api.get_reset_rules:load()


api.disable_rules:setup(server, yara)
api.disable_rules:load()

api.scan:setup(server, yara)
api.scan:load()

api.load_rule:setup(server, yara)
api.load_rule:load()

-- UI
ui:setup(config, logging, server)
ui:load()

-- tick
local time <const> = config:get("yaragate.rules.destroy.server.tick_time")
local destroy <const> = config:get("yaragate.rules.destroy.enabled")
if (destroy) then
    server:create_tick(60 * 1000, function()
        logging:debug("Calling tick for reset " .. tostring(yara.reset_time))
        yara.reset_time = yara.reset_time - 1
        if (yara.reset_time == 0) then
            yara:reset_rules()
            yara.reset_time = time
        end
    end)
else
    yara.reset_time = "∞"
end