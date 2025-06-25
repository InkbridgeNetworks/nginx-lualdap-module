lualdap-nginx (https://github.com/NetworkRADIUS/lualdap-nginx-module)

lualdap-nginx is a simple interface from Lua to an LDAP client.  It's designed to
work with lua-nginx's cosocket API.

    * Connect to an LDAP server;
    * Execute any operation (search, add, compare, delete, modify and rename);
    * Retrieve entries and references of the search result.

lualdap-nginx is free software and uses the same license as Lua 5.1.

Current version is 1.1.0. It was developed for LuaJit 2.1.

The original code for this project was taken from LuaLDAP but has been heavily
modified.

Please see CONTRIBUTORS for contribution information and documentation on original source

Note: This is a work in progress, and whilst it's used heavily within Inkbridge Networks
be aware that the code uses lua-nginx's private APIs, and compatibility with a given
version of NGINX or lua-nginx is not guaranteed.
