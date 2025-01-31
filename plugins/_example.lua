-- Logging levels based on spdlog
local LOG_LEVEL = {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5,
    OFF = 6
}

-- Utility function for logging with levels
function log(level, message)
    logging:log(level, message)
end

local clock = os.clock
function sleep(n)
    local t0 = clock()
    while clock() - t0 <= n do end
end

-- Check if the engine is running
if engine.is_running() then
    -- Log server details at INFO level
    log(LOG_LEVEL.INFO, '[@example] - Server bind address: ' .. server.bindaddr())
    log(LOG_LEVEL.INFO, "[@example] - Server port: " .. tostring(server.port()))
    log(LOG_LEVEL.INFO, "[@example] - Server concurrency: " .. tostring(server.concurrency()))

    -- Monitor engine status
    while engine.is_running() do
        sleep(1)
        log(LOG_LEVEL.DEBUG, "[@example] - Engine is running: " .. tostring(engine.is_running()))

        -- If engine stops, log at ERROR level
        if not engine.is_running() then
            log(LOG_LEVEL.ERROR, "[@example] - Engine is dead!")
        end
    end
else
    -- Log if the engine is not running at WARN level
    log(LOG_LEVEL.WARN, "[@example] - The engine is not running.")
end