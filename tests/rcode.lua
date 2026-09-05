--[[
Tests for the result code tables that the module exports.

lualdap.rcode.by_name maps the libldap macro name without the LDAP_ prefix
to the code. lualdap.rcode.by_number maps the code to the RFC 4511
identifier. The ldap-rcode endpoint returns both tables as JSON.
--]]

local luaunit = require('luaunit')


local m = {}

function m:TestResultCodeByName()
    local headers, json = self:sendRequest('GET', 'ldap-rcode')

    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.rcode.by_name.SUCCESS, 0)
    luaunit.assertEquals(json.rcode.by_name.NO_SUCH_OBJECT, 32)
    luaunit.assertEquals(json.rcode.by_name.INSUFFICIENT_ACCESS, 50)
    luaunit.assertEquals(json.rcode.by_name.PROXIED_AUTHORIZATION_DENIED, 123)
    luaunit.assertEquals(json.rcode.by_name.X_NO_OPERATION, 16654)
end

function m:TestResultCodeName()
    local _, json = self:sendRequest('GET', 'ldap-rcode')

    luaunit.assertEquals(json.rcode.by_number['0'], 'success')
    luaunit.assertEquals(json.rcode.by_number['32'], 'noSuchObject')
    luaunit.assertEquals(json.rcode.by_number['66'], 'notAllowedOnNonLeaf')
    luaunit.assertEquals(json.rcode.by_number['123'], 'authorizationDenied')
    luaunit.assertEquals(json.rcode.by_number['16654'], 'noOperation')
end

return m
