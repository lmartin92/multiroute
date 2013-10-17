-- This is the interface library
-- it's job is to enumerate every interface it can find
-- in iproute show and hand it to the libraries user
-- as something useable from within lua
--
-- usage:
--      local interface_enumerator = require("interface")
--      see test function for the rest of the example
--------------------------------------------------------------------

local interface_enumerator = {}
local interface = {}

--------------------------------------------------------------------
-- returns a new interface, pretty much an internal function
-- sets it up just enough for dynamic initialization upon
-- accessing its properties
--------------------------------------------------------------------
interface.new = function(name, inheritance)
    return
    {
        -- interface name
        name = name, 
        -- interface internals
        vals =
        {
            routes = inheritance.routes,
            ips = inheritance.ips
        },
        -- method to get information about the interface
        get = interface.get,
        -- internal method used by the interface
        -- for the get method
        parse = interface.parse,
    }
end

--------------------------------------------------------------------
-- gets the gw, nm, ip, name, and default, all of which
-- are properties of an interface
-- returns a string which is the value of one of those properties
--------------------------------------------------------------------
interface.get = function(self, what)
    ----------------------------------------------------------------
    -- internal function to turn the table
    -- returned by the other internal functions into
    -- a single value, basically the first value in the table
    -- had better be the answer (as that's the only thing it looks
    -- at)
    ----------------------------------------------------------------
    local function get_results()
        local res = self:parse(what)
        res = res or { none = "none" }
        for _, v in pairs(res) do
            return v
        end
    end
    
    -- test to see if we already have this value
    -- and if so do nothing, if not, initialize this value
    self.vals[what] = self.vals[what] or get_results()
    return self.vals[what]
end

--------------------------------------------------------------------
-- parses the text file looking for "what" in respect to the 
-- interface to which this method belongs
--------------------------------------------------------------------
interface.parse = function(self, what)
    ----------------------------------------------------------------
    -- returns a table containing net mask of this interface
    -- returns nil if can't find it
    ----------------------------------------------------------------
    local function nm()
        local ret = {}
        local set = false

        -- look thru all the text in ip route show line by line
        -- and if we find a match, add it into the return table
        -- and tell us to stop looking
        for i, l in ipairs(self.vals["routes"]) do
            if  l:find("dev") and
                l:find("scope") and
                l:find("link") and
                l:find("src") and
                l:find(self:get("name")) then
                table.insert(ret, l:sub(0, l:find("dev") - 1))
                set = true
            end
        end

        -- if we never set it, we are expected to return nil
        if set == false then
            ret = nil
        end

        -- if netmask has no /%d+ at the end, then give it a 
        -- /24 (which is suitable for our in_nm function
        -- to be able to recognize an ip in a /32 range as
        -- part of the same network
        local mask = ret[1]:match("%d+.%d+.%d+.%d+/(%d+)")
        if mask == nil then
            ret[1] = ret[1]:match("(%d+.%d+.%d+.%d+)") .. "/24"
        end

        return ret
    end

    ----------------------------------------------------------------
    -- returns a table containing the gateway
    -- returns nil if can't be found
    -- this function has never "failed" so... there is no
    -- check to turn ret to nil (probably this needs to be fixed)
    ----------------------------------------------------------------
    local function gw()
        local ret = {}

        -- if we are the default interface, the rules change
        -- on how to get our gateway
        if self:get("default") ~= "true" then
            -- find the gateway by going thru all the lines
            -- and checking if the line matches these credentials
            for _, l in ipairs(self.vals["routes"]) do
                if  l:find("dev") and
                    l:find("proto") and
                    l:find("kernel") and
                    l:find("scope") and
                    l:find("link") and
                    l:find("src") and
                    l:find(self:get("name")) then
                    table.insert(ret, l:sub(l:find("src") + 4, -1))
                end
            end
        else
            -- find the gateway by going thru all the lines
            -- and checking if the line matches these credentials
            for _, l in ipairs(self.vals["routes"]) do
                if  l:find("default") and
                    l:find("via") and
                    l:find(self:get("name")) then
                    table.insert(ret, 
                        l:sub(l:find("via") + 4, l:find("dev") - 1))
                end
            end
        end

        return ret
    end

    ----------------------------------------------------------------
    -- returns a table telling us this interface has the default     
    -- route, returns nil if can't be found
    -- since this function technically can't find nothing
    -- it returns false instead of nil, which may be wrong
    -- at some point in the future
    ----------------------------------------------------------------
    local function default()
        local ret = { "false" }

        -- goes thru the lines checking if anything matches
        -- these credentials
        for _, l in ipairs(self.vals["routes"]) do
            if  l:find("default") and
                l:find("via") and
                l:find(self:get("name")) then
                ret[1] = "true"
            end
        end

        return ret
    end

    ----------------------------------------------------------------
    -- returns a table telling us this interface's ip
    -- returns nil if can't be found
    -- probably should be able to pull this info from
    -- the text generated by ip addr show in the future
    ----------------------------------------------------------------
    local function ip()
        ------------------------------------------------------------
        -- turns an ip into octets and then into an integer
        ------------------------------------------------------------
        local function itol(ip_ip)
            if ip_ip == nil then
                return nil
            end

            local ret = 0
            local octets = {}
            -- get the octets in the ip_ip
            octets = { ip_ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)") }

            -- itterate over the octects, forming an integer along
            -- the way
            for _, v in ipairs(octets) do
                ret = bit32.bor(bit32.lshift(ret, 8), 
                        bit32.band(0xFF, v))
            end

            return ret
        end

        ------------------------------------------------------------
        -- tests an ip to see if it is within a net mask
        ------------------------------------------------------------
        local function in_nm(ip, net, mask)
            return bit32.band(itol(ip), mask) == net
        end

        ------------------------------------------------------------
        -- generates a netmask from CIDR form
        ------------------------------------------------------------
        local function genmask(mask)
            mask = mask or 0
            -- take mask, and then mask however many bits
            -- mask says to mask (integer amount)
            return bit32.lshift(0xFFFFFFF, 32 - mask)
        end

        local ret = {}
        local gw = self:get("gw"):match("(%d+%.%d+%.%d+%.%d+)")
        -- define pattern to extract ip
        local ip_pattern = "(%d+%.%d+%.%d+%.%d+)"
        local ip_nm = self:get("nm")
        -- split a netmask into it's ip and mask
        local net, mask = ip_nm:match("(%d+%.%d+%.%d+%.%d+)/(%d+)")
        -- turn the net part into an integer
        local hnet = itol(net)
        local set = false

        -- tests each line seeing if it matches these credentials
        -- and is in the network our netmask is
        -- and if true telling itself to ignore subsequent
        -- checks on lines
        for i, l in ipairs(self.vals["routes"]) do
            for m in l:gmatch(ip_pattern) do
                if  in_nm(m, hnet, genmask(mask)) and
                    m ~= net and
                    m ~= gw and
                    set ~= true and
                    l:find("via") == nil then
                    set = true
                    table.insert(ret,m)
                end
            end
        end

        -- if we didn't find it, we technically don't have an ip
        -- file a bug report if you find this function
        -- actually determines incorrectly in any case
        if set == false then
            ret = nil
        end

        return ret
    end

    ----------------------------------------------------------------
    -- returns the name of this interface
    ----------------------------------------------------------------
    local function name()
        return { name = self.name }
    end

    local funcs =
    {
        nm = nm,
        gw = gw,
        default = default,
        ip = ip,
        name = name
    }

    return funcs[what]()
end

--------------------------------------------------------------------
-- creates a new interface enumerator, fills it with enough
-- just to start off
--------------------------------------------------------------------
interface_enumerator.new = function()
    local t =
    {
        -- internal, routes from ip route show 
        -- (raw text line divided)
        routes = nil,
        -- internal, ips from ip addr show (raw text line divided)
        ips = nil,
        -- every interface sparsely initialized
        interfaces = {},
        -- method to enumerate the interfaces available in
        -- ip route show, does the sparse init of interfaces table
        enumerate = interface_enumerator.enumerate
    }
    return t
end

--------------------------------------------------------------------
-- enumerates the devices found in ip route
-- refresh argument is ignored for now 
--------------------------------------------------------------------
interface_enumerator.enumerate = function(self, refresh)

    ----------------------------------------------------------------
    -- gets text from a file in a table of lines
    ----------------------------------------------------------------
    local function get_text(what)
        local ret = {}
        local tf
        local rnd
        -- local add = (what == "route") and " table all" or ""
        local add = ""

        os.execute("ip " .. 
                    what .. 
                    " show" .. 
                    add .. 
                    "> ./" ..
                    tostring(rnd))
        tf = io.open("./" .. tostring(rnd))

        for l in tf:lines() do
            table.insert(ret, l)
        end
        tf:close()
        os.remove(tostring(rnd))

        return ret
    end

    ----------------------------------------------------------------
    -- finds every interface within ip routes show
    ----------------------------------------------------------------
    local function get_interfaces()
        local ret = {}

        for i, l in ipairs(self.routes) do
            where = l:find("dev")
            if where ~= nil then
                ret[l:sub(where+4, l:find(" ", where+4))] =
                l:sub(where+4, l:find(" ", where+4))
            end
        end

        return ret
    end

    refresh = refresh or false
    if refresh then
        self.routes = get_text("route")
        self.ips = get_text("addr")
    else
        self.routes = get_text("route")
        self.ips = get_text("addr")
    end

    local interfaces = get_interfaces()
    for _, v in pairs(interfaces) do
        self.interfaces[v] = self.interfaces[v] or 
            interface.new(v, self)
    end

    return interfaces
end

--------------------------------------------------------------------
-- the test function, used for debugging, and as an example
--------------------------------------------------------------------
local function test()
    local ifaces = interface_enumerator.new()
    ifaces:enumerate()
    for _, v in pairs(ifaces.interfaces) do
        print("name: " .. v:get("name"))
        print("ip: " .. v:get("ip")) 
        print("gw: " .. v:get("gw"))
        print("nm: " .. v:get("nm"))
        print("default:" .. v:get("default"))
        print()
    end
end

return 
    {
        new = interface_enumerator.new,
        test = test
    }
