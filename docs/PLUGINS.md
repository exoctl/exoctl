# 🗄 **Plugins Documentation**

## Overview  
This documentation explains how to integrate and use plugins in your engine, focusing on Lua scripting for interaction with the engine and server interfaces. It also provides an example script to monitor the engine's status and log server details.

---

## **Interfaces**

### **Engine**  
- **`is_running()`**  
  Checks if the engine's current status. Returns a boolean:  
  - `true`: The engine is running.  
  - `false`: The engine is not running.  

- **`concurrency()`**  
  Represents the server's concurrency level as an integer. This indicates how many tasks the server can handle simultaneously.

### **Server**  
- **`bindaddr()`**  
  Returns the server's bind address as a string. This is the IP address or hostname the server is bound to.  

- **`port()`**  
  Returns the server's port as an integer. This is the port number the server is listening on.  

---

## **Logging Levels**
Logging follows the `spdlog` standard levels:

- **TRACE (0)**: Detailed debug information.
- **DEBUG (1)**: Debug-level messages.
- **INFO (2)**: General informational messages.
- **WARN (3)**: Warnings that need attention.
- **ERROR (4)**: Errors that affect functionality.
- **CRITICAL (5)**: Serious errors that may require immediate action.
- **OFF (6)**: Disable logging.

---

## **Utility Functions**

### **`print_table(tbl)`**
A helper function to print key-value pairs of a given Lua table.
```lua
function print_table(tbl)
    for key, value in pairs(tbl) do
        print(key, value)
    end
end
```

### **`sleep(n)`**
Pauses execution for `n` seconds using `os.clock()`.
```lua
local clock = os.clock
function sleep(n)
    local t0 = clock()
    while clock() - t0 <= n do end
end
```

---

## **Example: Server Status Check and Monitoring**
The following Lua script checks if the engine is running, logs server details (bind address, port, and concurrency), and continuously monitors the engine's status until it stops.

```lua
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
    log(LOG_LEVEL.INFO, "[_example] - Server bind address: " .. server.bindaddr())
    log(LOG_LEVEL.INFO, "[_example] - Server port: " .. tostring(server.port()))
    log(LOG_LEVEL.INFO, "[_example] - Server concurrency: " .. tostring(server.concurrency()))

    -- Monitor engine status
    while engine.is_running() do
        sleep(1)
        log(LOG_LEVEL.DEBUG, "Engine is running: " .. tostring(engine.is_running()))

        -- If engine stops, log at ERROR level
        if not engine.is_running() then
            log(LOG_LEVEL.ERROR, "Engine is dead!")
        end
    end
else
    -- Log if the engine is not running at WARN level
    log(LOG_LEVEL.WARN, "[_example] - The engine is not running.")
end
```

This script improves monitoring by integrating structured logging with severity levels, making debugging and analysis easier.

