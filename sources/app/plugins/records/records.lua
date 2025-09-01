local api = {
    download = require("sources.app.plugins.records.download"):new(),
    strings = require("sources.app.plugins.records.strings"):new()
}
local server <const> = require("sources.app.plugins.records.server"):new()
local records_manager <const> = require("sources.app.plugins.records.records_manager"):new()

local config <const> = Configuration:new()
local logging <const> = Logging:new()

config:setup("sources/app/plugins/records/config.ini")
config:load()

logging:setup(config)
logging:load()

server:setup(config, logging)

records_manager:setup(config, logging)
records_manager:load()

api.strings:setup(server, records_manager)
api.strings:load()

api.download:setup(server, records_manager)
api.download:load()
