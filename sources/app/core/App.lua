require("build.sources.libexoctl")
Envvar = require("include.app.core.Envvar")

-- config engine
local config = Configuration.new()
local logging = Logging:new()
local engine = Engine:new()
local server = Server:new()
local bridge = Bridge:new()
local database = Database:new()

-- setup and load all config
config:setup(EXOCTLDIR .. "/config/exoctl.conf")
config:load()

logging:setup(config)
logging:load()

database:setup(config, logging)
database:load()

-- setup server (function 'run' is active in instance to engine)
server:setup(config, logging)
server:load()

bridge:setup(server)
bridge:load()

engine:setup(config, logging, server, database)
engine:load()
engine:run()