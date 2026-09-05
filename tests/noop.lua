--[[
Tests for the OpenLDAP No-Op Control support in the lualdap binding.

The tests:
  1. Bind as cn=manager,dc=example,dc=org (rootdn).
  2. Send each write operation (add, modify, delete, and rename) with
     noop=1.
  3. Assert that slapd answers LDAP_X_NO_OPERATION (0x410e, 16654) and
     that the directory is unchanged afterwards.
  4. Combine noop with proxy_id for a distinguished name (DN) that the
     container access control list (ACL) grants read only.
  5. Assert that slapd answers insufficientAccessRights (50), so a probe
     reports the access decision of the proxied identity.
--]]

local luaunit = require('luaunit')


local m = {}

local NO_OPERATION = 16654
local INSUFFICIENT_ACCESS = 50

-- The container ACL grants cn=testuser write and every other DN read only.
local READER_ID = 'dn:cn=ci_noop_reader,ou=users,dc=example,dc=org'
local TEST_DN = 'cn=ci_noop_test,dc=example,dc=org'
local TEST_RDN_NEW = 'cn=ci_noop_test_renamed'
local TEST_DN_NEW = TEST_RDN_NEW .. ',dc=example,dc=org'

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

-- Return the number of entries a base search for dn finds: 1 or 0.
local function entry_count(self, dn)
    local _, json = self:sendRequest('GET', 'ldap-search?' .. qs({
        base = dn,
        scope = 'base',
        filter = '(objectClass=*)',
        attrs = 'sn',
    }))
    if not json.ok then
        return 0
    end
    return #json.entries
end

local function entry_delete(self)
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN_NEW }))
end

function m:TestAddNoopCommitsNothing()
    self:finally(entry_delete)

    local headers, json = self:sendRequest('GET',
        'ldap-add?' .. qs({ dn = TEST_DN, noop = 1 }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertEquals(json.code, NO_OPERATION)
    luaunit.assertEquals(entry_count(self, TEST_DN), 0)
end

function m:TestDeleteNoopKeepsEntry()
    self:finally(entry_delete)
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))

    local headers, json = self:sendRequest('GET',
        'ldap-delete?' .. qs({ dn = TEST_DN, noop = 1 }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.code, NO_OPERATION)
    luaunit.assertEquals(entry_count(self, TEST_DN), 1)
end

function m:TestModifyNoopKeepsValue()
    self:finally(entry_delete)
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))

    local headers, json = self:sendRequest('GET',
        'ldap-modify?' .. qs({ dn = TEST_DN, attr = 'sn', val = 'noop_changed', noop = 1 }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.code, NO_OPERATION)

    local _, search = self:sendRequest('GET', 'ldap-search?' .. qs({
        base = TEST_DN,
        scope = 'base',
        filter = '(objectClass=*)',
        attrs = 'sn',
    }))
    luaunit.assertEquals(search.ok, true)
    luaunit.assertNotEquals(search.entries[1].attrs.sn, 'noop_changed')
end

function m:TestRenameNoopKeepsDn()
    self:finally(entry_delete)
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))

    local headers, json = self:sendRequest('GET',
        'ldap-rename?' .. qs({ dn = TEST_DN, newrdn = TEST_RDN_NEW, noop = 1 }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.code, NO_OPERATION)
    luaunit.assertEquals(entry_count(self, TEST_DN), 1)
    luaunit.assertEquals(entry_count(self, TEST_DN_NEW), 0)
end

function m:TestNoopWithProxyReportsAccessDecision()
    self:finally(entry_delete)
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))

    local headers, json = self:sendRequest('GET',
        'ldap-delete?' .. qs({ dn = TEST_DN, noop = 1, proxy_id = READER_ID }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.code, INSUFFICIENT_ACCESS)
    luaunit.assertEquals(entry_count(self, TEST_DN), 1)
end

return m
