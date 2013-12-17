lua-resty-scrypt
================

LuaJIT FFI-based scrypt library for OpenResty.

Usage
-----

```lua
local scrypt = require"scrypt"
local hash   = scrypt.crypt("My Secret")        -- returns a hash that can be stored in db
local valid  = scrypt.check("My Secret", hash)  -- valid holds true
local valid  = scrypt.check("My Guess",  hash)  -- valid holds false

local n,r,p  = scrypt.calibrate()               -- returns n,r,p calibration values
```

