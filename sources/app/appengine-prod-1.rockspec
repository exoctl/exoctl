package = "appengine"
version = "prod-1"

source = {
   url = "",
   md5 = ""
}

description = {
   summary = "This application for libexoctl",
   homepage = "",
   license = ""
}

dependencies = {
   "lua <= 5.4",
   "lua-zlib",
   "luafilesystem",
   "lua-cjson"
}

build = {
   type = "builtin",
   modules = {
      appengine = "core/App.lua",
      memorycheck = "core/MemoryCheck.lua",
      ptracedetector = "core/PTraceDetector.lua",
      utils = "core/Utils.lua",
      dump = "core/Dump.lua"
   }
}