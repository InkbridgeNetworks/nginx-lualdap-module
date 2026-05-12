package = "lualdap-nginx-tests"
version = "dev-1"

source = {
   url = "file://."
}

description = {
   summary  = "Test-suite dependencies for nginx-lualdap-module",
   detailed = [[
      Pure-Lua dependencies required to run tests/*.lua against a
      running nginx + LuaLDAP module. Install with:

          luarocks --lua-version 5.4 make lualdap-nginx-tests-dev-1.rockspec

      The test runner (bin/run_tests) also requires the `dapman-http-unit`
      module from the parent SubMan project. It is not declared here
      because it lives outside this submodule; either install it via its
      own rockspec or place it on LUA_PATH before running the tests.
   ]],
   homepage = "https://github.com/InkbridgeNetworks/nginx-lualdap-module",
   license  = "Commercial"
}

dependencies = {
   "lua >= 5.1, < 5.5",
   "luaunit ~> 3.5",
   "lua-cjson",
   "luasocket",
   "cqueues",
   "http",
}

build = {
   type    = "builtin",
   modules = {}
}
