# 📄 **Plugins Documentation**

## Overview  
This documentation explains how to integrate and use plugins in your engine, focusing on Lua scripting for interaction with the engine and server interfaces.

---

## **Interfaces**

### **Engine**  
- **`is_running()`**  
  Checks if the engine is currently running. Returns a boolean:  
  - `true`: The engine is running.  
  - `false`: The engine is not running.  

### **Server**  
- **`bindaddr`**  
  Represents the server's bind address as a string.  

- **`port`**  
  Represents the server's port as an integer.  

---

## **Getting Started with Lua Scripts**

### **Example: Server Status Check**
The following Lua script demonstrates how to check if the engine is running and log server details such as the bind address and port.  

```lua
-- Check if the engine is running
if engine.is_running() then
    -- Log the server's bind address and port
    print("[_example] - server.bindaddr = " .. server.bindaddr())
    print("[_example] - server.port = " .. tostring(server.port()))
else
    print("[_example] - The engine is not running.")
end

-- Finalize function (called automatically when the engine shuts down)
function _finalize()
    print("[_example] - The engine has been stopped!")
end
