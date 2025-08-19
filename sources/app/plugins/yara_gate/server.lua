local server = { config = nil, logging = nil }

function server:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function server:setup(config, logging)
    self.logging = logging
    self.config = config
end

function server:create_route(route, handler)
    Web.new(_engine.server, self.config:get("yara.server.gateway.prefix") .. route, function(req)
        self.logging:info(("Request received: method={%s}, url={%s}, remote_ip={%s}, http_version={%d.%d}, keep_alive={%s}")
            :format(req.method, req.url, req.remote_ip_address, req.http_ver_major, req.http_ver_minor,
                req.keep_alive)
        )
        return handler(req)
    end)
end

return server