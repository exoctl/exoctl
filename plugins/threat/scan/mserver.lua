local MServer = { Config = nil, Logging = nil, Server = nil }

function MServer:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function MServer:setup(config, logging)
    self.Logging = logging
    self.Config = config
    self.Server = Server:new()
    self.Server:setup(config, logging)
end

function MServer:load()
    self.Server:load()
end

function MServer:create_route(route, methods, handler)
    Web.new(self.Server, self.Config:get("threat.gateway.prefix") .. route, function(req)
        self.Logging:info(("Request received: method={%s}, url={%s}, remote_ip={%s}, http_version={%d.%d}, keep_alive={%s}")
            :format(req.method, req.url, req.remote_ip_address, req.http_ver_major, req.http_ver_minor,
                req.keep_alive)
        )
        return handler(req)
    end, methods)
end

function MServer:create_tick(time, func)
    self.Server:tick(time, func)
end

function MServer:run()
    self.Server:run_async()
end

return MServer
