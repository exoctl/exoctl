local strings = { server = nil, records_manager = nil }

function strings:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function strings:setup(server, records_manager)
    self.server = server
    self.records_manager = records_manager
end

function strings:load()
    self.server:create_route("/extract/strings", function(req)
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

        local content <const> = self.records_manager:extract_strings(file)

        local json_strings = Json:new()
        for i, str in ipairs(content) do
            json_strings:add(str)
        end

        if (content == nil or content == "") then
            return self:create_error_response(404, "File not found")
        end

        return Response:new(200, json_strings:tostring())
    end)
end

return strings