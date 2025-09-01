local download = { server = nil, records_manager = nil }

function download:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function download:setup(server, records_manager)
    self.server = server
    self.records_manager = records_manager
end

function download:load()
    self.server:create_route("/download", function(req)
        if not req.body or req.body == "" then
            return self:create_error_response(400, "Invalid request body")
        end

        local json = Json:new()

        local parse_success = pcall(function() json:from_string(req.body) end)
        if not parse_success then
            return self:create_error_response(400, "Invalid JSON format")
        end

        local file = json:get("sha256")
        if not file or type(file) ~= "string" or file == "" then
            return self:create_error_response(400, "Missing or invalid field: 'sha256' is required")
        end

        local content <const> = self.records_manager:read(file)

        if (content == nil or content == "") then
            return self:create_error_response(404, "File not found")
        end

        return Response:new(200, content)
    end)
end

function download:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:tostring())
end

return download
