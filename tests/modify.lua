local luaunit = require('luaunit')


local m = {}

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

local MODIFY_DN = 'cn=ci_modify_target,dc=example,dc=org'
-- ou=users always exists and allows description; used for schema-error test.
local REAL_DN   = 'ou=users,dc=example,dc=org'

function m:TestModifySuccess()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = MODIFY_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = 'ci-test-value' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
end

function m:TestMissingDn()
    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ attr = 'description', val = 'x' }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

function m:TestMissingAttr()
    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, val = 'x' }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

function m:TestMissingVal()
    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description' }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

function m:TestNonexistentDn()
    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = 'cn=__ghost__,dc=example,dc=org', attr = 'description', val = 'x' }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertNotNil(json.code)
end

function m:TestUnknownAttribute()
    -- Setting an attribute that doesn't exist in the schema should fail.
    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = REAL_DN, attr = 'unknownAttr99x', val = 'x' }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertNotNil(json.code)
end

return m
