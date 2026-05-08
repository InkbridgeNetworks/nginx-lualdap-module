local luaunit = require('luaunit')


local m = {}

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

local TEST_DN = 'cn=ci_delete_test,dc=example,dc=org'

function m:TestDeleteSuccess()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))

    local headers, json = self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
end

function m:TestDeleteNonexistent()
    local headers, json = self:sendRequest('GET',
        'ldap-delete?' .. qs({ dn = 'cn=__ghost__,dc=example,dc=org' }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertNotNil(json.code)
end

function m:TestMissingDn()
    local headers, json = self:sendRequest('GET', 'ldap-delete')
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

return m
