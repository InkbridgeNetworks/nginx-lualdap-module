local luaunit = require('luaunit')


local m = {}

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

local BASE        = 'dc=example,dc=org'
local SRC_DN      = 'cn=ci_rename_src,dc=example,dc=org'
local DST_RDN     = 'cn=ci_rename_dst'
local DST_DN      = DST_RDN .. ',' .. BASE

function m:TestRenameSuccess()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = SRC_DN }))
    self:finally(function(self)
        -- Cleanup either name in case of failure mid-way
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SRC_DN }))
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DST_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-rename?' .. qs({ dn = SRC_DN, newrdn = DST_RDN, deleteoldrdn = 1 }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DST_DN }))
end

function m:TestRenameNonexistentDn()
    local headers, json = self:sendRequest('GET',
        'ldap-rename?' .. qs({ dn = 'cn=__ghost__,dc=example,dc=org', newrdn = 'cn=whatever' }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertNotNil(json.code)
end

function m:TestMissingNewrdn()
    local headers, json = self:sendRequest('GET',
        'ldap-rename?' .. qs({ dn = SRC_DN }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

function m:TestMissingDn()
    local headers, json = self:sendRequest('GET',
        'ldap-rename?' .. qs({ newrdn = 'cn=whatever' }))
    luaunit.assertEquals(headers:get(':status'), 400)
    luaunit.assertEquals(json.ok, false)
end

function m:TestRenameAlreadyRenamed()
    -- After a successful rename, the original DN no longer exists so a second
    -- rename from the same source should fail.
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = SRC_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = SRC_DN }))
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DST_DN }))
    end)

    self:sendRequest('GET',
        'ldap-rename?' .. qs({ dn = SRC_DN, newrdn = DST_RDN, deleteoldrdn = 1 }))

    local headers, json = self:sendRequest('GET',
        'ldap-rename?' .. qs({ dn = SRC_DN, newrdn = DST_RDN, deleteoldrdn = 1 }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)

    self:finallyPop()
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = DST_DN }))
end

return m
