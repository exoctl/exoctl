package = "appengine"
version = "prod-1"

source = {
   url = "",
   md5 = ""
}

description = {
   summary = "This application for libskull",
   homepage = "http://maldec.io",
   license = ""
}

dependencies = {
   "lua <= 5.4",
   "http",
   "lua-zlib",
   "luafilesystem",
   "lua-cjson"
}

build = {
   type = "builtin",
   modules = {
      appengine = "sources/App.lua",
      memorycheck = "sources/MemoryCheck.lua",
      ptracedetector = "sources/PTraceDetector.lua",
      utils = "sources/Utils.lua",
      dump = "sources/Dump.lua"
   }
}