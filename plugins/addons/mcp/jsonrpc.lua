local JsonRpc = {}

function JsonRpc:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function JsonRpc:register_method(name, func)
    self.methods[name] = func
end

function JsonRpc:handle_request(request_json)
    if request_json:get("jsonrpc") ~= "2.0" or not request_json:get("method") then
        local error_response = Json:new()
        error_response:add("jsonrpc", "2.0")
        error_response:add("error", Json:new():add("code", -32600):add("message", "Invalid Request"))
        error_response:add("id", request_json:get("id"))
        return error_response
    end

    local method = self.methods[request_json:get("method")]

    if not method then
        local error_response = Json:new()
        error_response:add("jsonrpc", "2.0")
        error_response:add("error", Json:new():add("code", -32601):add("message", "Method not found"))
        error_response:add("id", request_json:get("id"))
        return error_response
    end

    local success, result = pcall(method, request_json:get("params"))
    local response = Json:new()
    response:add("jsonrpc", "2.0")
    response:add("id", request_json:get("id"))

    if success then
        response:add("result", result)
    else
        response:add("error", Json:new():add("code", -32603):add("message", "Internal error: " .. result))
    end

    return response
end

return JsonRpc
