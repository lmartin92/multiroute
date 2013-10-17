local serial = require("tserialize")
local serializer = {}

-- serializes a table t to file where
serializer.serialize = function(t, where, name)
   local f = io.open(where, "w+")
   f:write(table.serialize(name, t))
   f:write("\nreturn " .. name)
   f:close()
end

-- deserializes a table named name in a file where
-- returns table
serializer.deserialize = function(name) 
    local ret = require(name)
    return ret
end

-- tests serialization works 
-- we only want real values anyway, not functions
-- in tables serialized
local function test() 
    local t = {
        boo = 10,
        20,
        { booger = 40,
            50 }
    }   

    serializer.serialize(t, "dang.lua", "dang")
    for i, v in pairs(serializer.deserialize("dang")) do
        if type(v) == "table" then
            for i2, v2 in pairs(v) do
                print(i2,v2)
            end
        end
        print(i,v)
    end
end

return {
    serialize = serializer.serialize,
    deserialize = serializer.deserialize
}
