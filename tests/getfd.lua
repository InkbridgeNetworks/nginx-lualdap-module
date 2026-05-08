local luaunit = require('luaunit')


local m = {}

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

function m:TestGetFdReturnsValidFd()
    local headers, json = self:sendRequest('GET', 'ldap-getfd')
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertNotNil(json.fd)
    luaunit.assertIsTrue(json.fd > 0)
end

function m:TestGetFdBadPort()
    local headers, json = self:sendRequest('GET',
        'ldap-getfd?' .. qs({ port = 1 }))
    luaunit.assertEquals(headers:get(':status'), 502)
    luaunit.assertEquals(json.ok, false)
end

return m
