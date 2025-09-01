local records_manager = { config = nil, logging = nil, string_min_length = nil }

function records_manager:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function records_manager:setup(config, logging)
    self.config = config
    self.logging = logging

    self.string_min_length = self.config:get("records.strings.min_length")
end

function records_manager:load()
    -- nothing just for pattern code
end

function records_manager:read(sha256)
    local file = File:new()
    file.filename = sha256

    _engine.filesystem:read(file, true)

    local content = file.content
    if (content == nil or content == "") then
        print(self.logging)
        self.logging:warn(string.format("File with sha256 {%s} not found or empty", sha256))
        return {}
    end

    return content
end

function records_manager:extract_strings(sha256)
    local content <const> = self:read(sha256)

    if (content == nil or content == "") then
        return {}
    end

    local strings = {}
    local current_string = ""

    for i = 1, #content do
        local byte = string.byte(content, i)
        if byte >= 32 and byte <= 126 then
            current_string = current_string .. string.char(byte)
        else
            if #current_string >= self.string_min_length then
                table.insert(strings, current_string)
            end
            current_string = ""
        end
    end

    if #current_string >= self.string_min_length then
        table.insert(strings, current_string)
    end

    return strings
end

return records_manager
