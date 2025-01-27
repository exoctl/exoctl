-- Check if the engine is running
if engine.is_running() then
    -- Log the server's bind address and port
    print("[_example] - server.bindaddr = " .. server.bindaddr())
    print("[_example] - server.port = " .. tostring(server.port()))
    print("[_example] - server.concurrency = " .. tostring(server.concurrency()))

    while engine.is_running() do
    end
  
else
    print("[_example] - The engine is not running.")
end

-- Finalize function (called automatically when the engine shuts down)
function _finalize()
    print("[_example] - The engine has been stopped!")
end