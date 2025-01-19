if engine.is_running() then
    print("[_test] - server.bindaddr = " .. server.bindaddr())
    print("[_test] - server.port = " .. tostring(server.port()))
end

function _finalize ()
    print("[_test] - engine is dead !")
end