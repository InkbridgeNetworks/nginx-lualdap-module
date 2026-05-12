--[[
Coverage for the RFC 4370 Proxy Authorisation Control wiring.

Strategy:
  - Bind as cn=manager,dc=example,dc=org (rootdn, free use of proxy authz).
  - Use proxy_id="dn:cn=testuser,ou=users,dc=example,dc=org". The container
    is bootstrapped with an olcAccess rule giving testuser write access to
    dc=example,dc=org (see ldap-container.sh).

For mutating ops (add, modify, delete, rename) we read back creatorsName
and modifiersName via the search endpoint and assert that the proxy DN
ended up recorded — the strongest end-to-end proof that the control was
sent and applied by the server.

For compare/search/search_persistent we just exercise the wiring (success
+ control-array threading) since these reads don't update operational
attributes we can verify the same way.
--]]

local luaunit  = require('luaunit')


local m = {}

local PROXY_DN = 'cn=testuser,ou=users,dc=example,dc=org'
local PROXY_ID = 'dn:' .. PROXY_DN
local TEST_DN  = 'cn=ci_proxy_test,dc=example,dc=org'

local function qs(params)
    local parts = {}
    for k, v in pairs(params) do
        parts[#parts + 1] = k .. "=" .. tostring(v)
    end
    return table.concat(parts, '&')
end

-- Read creatorsName / modifiersName from a single entry via the search endpoint.
local function read_op_attrs(self, dn)
    local _, json = self:sendRequest('GET', 'ldap-search?' .. qs({
        base   = dn,
        scope  = 'base',
        filter = '(objectClass=*)',
        attrs  = 'creatorsName,modifiersName',
    }))
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(#json.entries, 1)
    return json.entries[1].attrs
end


function m:TestAddRecordsProxyAsCreator()
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    end)

    local headers, json = self:sendRequest('GET',
        'ldap-add?' .. qs({ dn = TEST_DN, proxy_id = PROXY_ID }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    local attrs = read_op_attrs(self, TEST_DN)
    luaunit.assertEquals(attrs.creatorsName, PROXY_DN)
    luaunit.assertEquals(attrs.modifiersName, PROXY_DN)
end


function m:TestModifyRecordsProxyAsModifier()
    -- Seed the entry as manager so creatorsName starts as manager;
    -- the modify-as-proxy must overwrite modifiersName but leave creatorsName.
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    end)

    local headers, json = self:sendRequest('GET', 'ldap-modify?' .. qs({
        dn       = TEST_DN,
        attr     = 'description',
        val      = 'proxy-modify',
        proxy_id = PROXY_ID,
    }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    local attrs = read_op_attrs(self, TEST_DN)
    luaunit.assertEquals(attrs.modifiersName, PROXY_DN)
    -- Sanity: creatorsName should still be the manager that did the seed add.
    luaunit.assertEquals(attrs.creatorsName, 'cn=manager,dc=example,dc=org')
end


function m:TestRenameRecordsProxyAsModifier()
    local renamed_dn = 'cn=ci_proxy_test_renamed,dc=example,dc=org'

    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))
    self:finally(function(self)
        -- Best-effort cleanup of either name.
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = renamed_dn }))
    end)

    local headers, json = self:sendRequest('GET', 'ldap-rename?' .. qs({
        dn       = TEST_DN,
        newrdn   = 'cn=ci_proxy_test_renamed',
        proxy_id = PROXY_ID,
    }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    local attrs = read_op_attrs(self, renamed_dn)
    luaunit.assertEquals(attrs.modifiersName, PROXY_DN)
end


function m:TestDeleteWithProxySucceeds()
    -- We can't read modifiersName off a deleted entry, so this just proves
    -- the delete went through under proxy authz. A non-200 response from
    -- the delete would indicate the proxy got rejected.
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))

    local headers, json = self:sendRequest('GET',
        'ldap-delete?' .. qs({ dn = TEST_DN, proxy_id = PROXY_ID }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)

    -- Confirm the entry is actually gone (subtree search with a narrow
    -- filter; an empty result set proves deletion regardless of how the
    -- search endpoint represents "no such object").
    local _, search_json = self:sendRequest('GET', 'ldap-search?' .. qs({
        base   = 'dc=example,dc=org',
        scope  = 'sub',
        filter = '(cn=ci_proxy_test)',
    }))
    luaunit.assertEquals(#search_json.entries, 0)
end


function m:TestCompareWithProxySucceeds()
    self:sendRequest('GET', 'ldap-add?' .. qs({ dn = TEST_DN }))
    self:finally(function(self)
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    end)

    -- TEST_DN.cn == "ci_proxy_test" by ldap-add's derivation rule.
    local headers, json = self:sendRequest('GET', 'ldap-compare?' .. qs({
        dn       = TEST_DN,
        attr     = 'cn',
        val      = 'ci_proxy_test',
        proxy_id = PROXY_ID,
    }))
    luaunit.assertEquals(headers:get(':status'), 200)
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(json.result, true)
end


function m:TestSearchWithProxySucceeds()
    local _, json = self:sendRequest('GET', 'ldap-search?' .. qs({
        base     = 'dc=example,dc=org',
        scope    = 'base',
        filter   = '(objectClass=*)',
        proxy_id = PROXY_ID,
    }))
    luaunit.assertEquals(json.ok, true)
    luaunit.assertEquals(#json.entries, 1)
end


function m:TestProxyToUnprivilegedUserIsRejected()
    -- Negative coverage: cn=anonprobe (no ACL for it) lacks write access to
    -- dc=example,dc=org. If proxy_id is correctly applied by the server,
    -- the add fails with insufficient access (LDAP code 50). If the proxy_id
    -- were silently dropped (regression), manager's rootdn priv would let it
    -- succeed. Either failure mode is testable.
    self:finally(function(self)
        -- Cleanup in case the bug ever lets it through.
        self:sendRequest('GET', 'ldap-delete?' .. qs({ dn = TEST_DN }))
    end)

    local headers, json = self:sendRequest('GET', 'ldap-add?' .. qs({
        dn       = TEST_DN,
        proxy_id = 'dn:cn=anonprobe,dc=example,dc=org',
    }))
    luaunit.assertEquals(headers:get(':status'), 500)
    luaunit.assertEquals(json.ok, false)
    luaunit.assertEquals(json.code, 50)
end


return m
