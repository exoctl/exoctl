package.cpath = "build/sources/?.so;" .. package.cpath

require("libengine")

config = Configuration.new()
logging = Logging.new()
engine = Engine.new()

config.path = "config/engine/engine.conf"
config:load()
config:register_plugins()

logging.config = config
logging:load()
logging:register_plugins()

engine:setup(config, logging)
engine:register_plugins()

engine:run()
