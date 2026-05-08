local luaunit = require('luaunit')


local m = {}

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

local TEST_DN = 'cn=ci_add_test,dc=example,dc=org'

function m:TestAddSuccess()
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    end)

    local headers, json = self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
end

function m:TestAddDuplicate()
    -- Add once
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    end)

    -- Second add should fail
    local headers, json = self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertNotNil(json.code)

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
end

function m:TestMissingDn()
    local headers, json = self:sendRequest('GET', 'ldap-add')
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

function m:TestBadDnFormat()
    -- ldap-add requires dn to start with cn=
    local headers, json = self:sendRequest('GET',
        'ldap-add?' .. qs({ dn = 'uid=someone,dc=example,dc=org' }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

return m
