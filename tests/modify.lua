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

--- Read one attribute of MODIFY_DN back through the search endpoint
---
--- @param self table   test object
--- @param attr string  attribute to read
--- @return any value   the attribute value as the search handler returns it, nil when absent
local function attribute_read(self, attr)
    local headers, json = self:sendRequest('GET',
        'ldap-search?' .. qs({ base = MODIFY_DN, scope = 'base', filter = '(objectClass=*)', attrs = attr }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(#json.entries, 1)

    return json.entries[1].attrs[attr]
end

-- The binding stores a boolean as the LDAP Boolean literal, so a boolean
-- that reaches the binding is a value, never an instruction.
function m:TestModifyBooleanIsStoredAsLiteral()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = MODIFY_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = 'true', type = 'boolean' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(attribute_read(self, 'description'), 'TRUE')

    headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = 'false', type = 'boolean' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(attribute_read(self, 'description'), 'FALSE')

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
end

-- A number is one value, the digits of the number.
function m:TestModifyNumberIsStoredAsDigits()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = MODIFY_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = '42', type = 'number' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(attribute_read(self, 'description'), '42')

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
end

-- A NULL lightuserdata, cjson.null, means no values, so a replace with null
-- removes the attribute.
function m:TestModifyNullRemovesTheAttribute()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = MODIFY_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = 'present' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(attribute_read(self, 'description'), 'present')

    headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', type = 'null' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertNil(attribute_read(self, 'description'))

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
end

-- A sequence is many values.
function m:TestModifyListIsManyValues()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = MODIFY_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = 'one,two', type = 'list' }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    local values = attribute_read(self, 'description')
    table.sort(values)
    luaunit.assertEquals(values, { 'one', 'two' })

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
end

-- A table with a named key is a decoded JSON object, which has no value the
-- directory could hold. The binding refuses the table instead of sending the
-- attribute with no values, which a replace would read as a removal.
function m:TestModifyObjectIsRefused()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = MODIFY_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = MODIFY_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = 'kept' }))
    luaunit.assertEquals(headers:get(':status'), 200)

    headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = MODIFY_DN, attr = 'description', val = 'a', type = 'object' }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertStrContains(json.err, 'keys outside the sequence')
    luaunit.assertEquals(attribute_read(self, 'description'), 'kept')

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
