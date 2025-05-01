require("libinfinity")
Envvar = require("Envvar")
Telemetria = require("Telemetria")

-- config engine
local telemetria = Telemetria:new()
local config = Configuration.new()
local logging = Logging:new()
local engine = Engine.new()
local server = Server.new()
local bridge = Bridge.new()

-- register emergency for receive signals engine
engine:register_emergency(11, function(sig, siginfo, context)
    local err =
    "Engine received an emergency signal 11 (SIGSEGV), occur frequently contact support"
    logging:error(err)
    error(err, 1)
end)


-- setup and load all config
config:setup(INFINITYDIR .. "/config/infinity.conf")
config:load()

logging:setup(config)
logging:load()

-- setup server (function 'run' is active in instance to engine)
server:setup(config, logging)
server:load()

bridge:setup(server)
bridge:load()

engine:setup(config, logging, server)
if (engine.register_plugins) then
    engine:register_plugins()
end
engine:load()

engine:run(function() -- running in thread function
    telemetria:check_tracing()
    telemetria:check_mem()
end)
