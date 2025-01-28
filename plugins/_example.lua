function print_table(tbl)
    for key, value in pairs(tbl) do
        print(key, value)
    end
end

-- Local reference to the OS clock for timing
local clock = os.clock

-- Function to create a delay (sleep) for a specified number of seconds
function sleep(n) -- n: number of seconds to sleep
    local t0 = clock()
    while clock() - t0 <= n do end
end

-- stop engine 
-- engine:stop()

-- Check if the engine is running
if engine.is_running() then
    -- Log the server's bind address, port, and concurrency
    print("[_example] - server.bindaddr = " .. server.bindaddr())
    print("[_example] - server.port = " .. tostring(server.port()))
    print("[_example] - server.concurrency = " .. tostring(server.concurrency()))

    -- Continuously monitor the engine's status
    while engine.is_running() do
        sleep(1) -- Sleep for 1 second
        print("Engine is running: " .. tostring(engine.is_running()))

        -- Check if the engine has stopped
        if not engine.is_running() then
            print("Engine is dead!")
        end
        
    end
else
    -- Log if the engine is not running
    print("[_example] - The engine is not running.")
end