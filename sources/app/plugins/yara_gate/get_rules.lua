local get_rules = { server = nil, yara_manager = nil }

function get_rules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function get_rules:setup(server, yara_manager)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(yara_manager) == "table", "Invalid yara_manager instance")

    self.server = server
    self.yara_manager = yara_manager
end

function get_rules:load()
    self.server:create_route("/rules", function(req)
        local rules_json = Json:new()
        local count = 0

        if not self.yara_manager or not self.yara_manager.is_life then
            return self:create_error_response(500, "Yara engine is not initialized")
        end
        self.yara_manager.yara:rules_foreach(function(rules)
            if rules then
                count = count + 1
                local meta = Json:new()
                self.yara_manager.yara:metas_foreach(rules, function(metas)
                    if metas then
                        local value = (metas.type ~= 2) and metas.integer or metas.string
                        meta:add(metas.identifier, value)
                    end
                end)

                local string = Json:new()
                self.yara_manager.yara:strings_foreach(rules, function(strings)
                    if strings then
                        local json_string = Json:new():add("identifier", strings.identifier):add("length",
                            strings.length):add("index", strings.idx):add("string", strings.string):add("flags",
                            strings.flags)

                        string:add(json_string)
                    end
                end)


                local tag = Json:new()
                self.yara_manager.yara:tags_foreach(rules, function(tags)
                    if tags then
                        tag:add(tags)
                    end
                end)

                local rule = Json:new():add("identifier", rules.identifier):add("namespace",
                    (rules.ns and rules.ns.name)):add("num_atoms", rules.num_atoms):add("meta", meta):add("strings",
                    string):add("flags", rules.flags):add("tags", tag)

                rules_json:add(rule)
            end
        end)

        return Response:new(200, "application/json", Json:new():add("rules", rules_json):add("count", count):tostring())
    end)
end

function get_rules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:tostring())
end

return get_rules
