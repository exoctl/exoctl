local Server = { Config = nil, Logging = nil }

function Server:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function Server:setup(config, logging)
    self.Logging = logging
    self.Config = config
end

function Server:create_route(route, methods, handler)
    Web.new(_engine.server, self.Config:get("yaragate.gateway.prefix") .. route, function(req)
        self.Logging:info(("Request received: method={%s}, url={%s}, remote_ip={%s}, http_version={%d.%d}, keep_alive={%s}")
            :format(req.method, req.url, req.remote_ip_address, req.http_ver_major, req.http_ver_minor,
                req.keep_alive)
        )
        return handler(req)
    end, methods)
end

function Server:create_tick(time, func)
    _engine.server:tick(time, func)
end

return Server
