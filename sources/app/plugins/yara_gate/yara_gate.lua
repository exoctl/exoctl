-- ========================
-- Initialization and Configuration
-- ========================

local config <const> = Configuration:new()
local logging <const> = Logging:new()
local server <const> = require("sources.app.plugins.yara_gate.server"):new()


local api <const> = {
    get_rules = require("sources.app.plugins.yara_gate.get_rules"):new(),
    set_disable_rules = require("sources.app.plugins.yara_gate.set_disable_rules"):new(),
    set_enable_rules = require("sources.app.plugins.yara_gate.set_enable_rules"):new(),
    get_compiled_rules = require("sources.app.plugins.yara_gate.get_compiled_rules"):new(),
    set_load_rules = require("sources.app.plugins.yara_gate.set_load_rules"):new(),
}

local yara_manager <const> = require("sources.app.plugins.yara_gate.yara_manager"):new()


-- ========================
-- Setup and Load Configuration
-- ========================

config:setup("sources/app/plugins/yara_gate/config.ini")
config:load()

logging:setup(config)
logging:load()

yara_manager:setup(config, logging)
yara_manager:load()


server:setup(config, logging)

-- APis

api.set_enable_rules:setup(server, yara_manager)
api.set_enable_rules:load()

api.set_load_rules:setup(server, yara_manager)
api.set_load_rules:load()

api.set_disable_rules:setup(server, yara_manager)
api.set_disable_rules:load()

api.get_compiled_rules:setup(server, yara_manager)
api.get_compiled_rules:load()

api.get_rules:setup(server, yara_manager)
api.get_rules:load()

-- api.enable_rules:setup(server, yara)
-- api.enable_rules:load()

-- api.get_compiled_rules:setup(server, yara)
-- api.get_compiled_rules:load()

-- api.get_reset_rules:setup(server, yara)
-- api.get_reset_rules:load()


-- api.disable_rules:setup(server, yara)
-- api.disable_rules:load()

-- api.scan:setup(server, yara)
-- api.scan:load()

-- api.load_rule:setup(server, yara)
-- api.load_rule:load()

-- -- UI
-- ui:setup(config, logging, server)
-- ui:load()
