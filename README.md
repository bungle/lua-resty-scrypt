# lua-resty-scrypt

`lua-resty-scrypt` is a scrypt (password) hashing library for OpenResty.

## Hello World with lua-resty-scrypt

```lua
local scrypt = require "resty.scrypt"
local hash   = scrypt.crypt "My Secret"         -- returns a hash that can be stored in db
local valid  = scrypt.check("My Secret", hash)  -- valid holds true
local valid  = scrypt.check("My Guess",  hash)  -- valid holds false

local n,r,p  = scrypt.calibrate()               -- returns n,r,p calibration values
```

## Installation

Just place [`scrypt.lua`](https://github.com/bungle/lua-resty-scrypt/blob/master/lib/resty/scrypt.lua) somewhere in your `package.path`, preferably under `resty` directory. If you are using OpenResty, the default location would be `/usr/local/openresty/lualib/resty`.

### Compiling and Installing Scrypt C-library

These are just rudimentary notes. Better installation instructions will follow:

1. First download Scrypt from here: https://github.com/bungle/lua-scrypt
2. Run `make`
4. Place `scrypt.so|scrypt.dylib|scrypt.dll` somewhere in the default search path for dynamic libraries of your operating system (or modify `scrypt.lua` and point `ffi_load("scrypt")` with full path to `scrypt.so|scrypt.dylib|scrypt.dll`, e.g. `local scrypt = ffi_load("/usr/local/lib/lua/5.1/scrypt.so")`).

### Using LuaRocks or MoonRocks

If you are using LuaRocks >= 2.2:

```Shell
$ luarocks install lua-resty-scrypt
```

If you are using LuaRocks < 2.2:

```Shell
$ luarocks install --server=http://rocks.moonscript.org moonrocks
$ moonrocks install lua-resty-scrypt
```

MoonRocks repository for `lua-resty-scrypt`  is located here: https://rocks.moonscript.org/modules/bungle/lua-resty-scrypt.

## Lua API

#### string scrypt.crypt(opts)

Uses scrypt algorithm to generate hash from the input. Input parameter `opts` can
either be `string` (a `secret`) or a table. If it is a table you may pass in some
configuration parameters as well. Available table options (defaults are as follows):

```lua
local opts = {
    secret   = "",
    keysize  = 32,
    n        = 32768,
    r        = 8,
    p        = 1,
    salt     = "random (saltsize) bytes generated with OpenSSL",
    saltsize = 8
}
```

If you pass opts anything other than a table, it will be `tostring`ified and used
as a `secret`. `keysize` can be between 16 and 512, `saltsize` can be between 8
and 32.

This function returns string that looks like this:

```lua
n$r$p$salt$hash
```

All parts present a `hex dump` of their values.

##### Example

```lua
local h1 = scrypt.crypt "My Secret"
local h2 = scrypt.crypt{
    secret  = "My Secret",
    keysize = 512 
}
```

#### boolean scrypt.check(secret, hash)

With this function you can check if the `secret` really matches with the `hash` that
was generated with `scrypt.crypt` from the same `secret`. The `hash` contains also the
configuration parameters like `n`, `r`, `p` and `salt`.

##### Example

```lua
local b1 = scrypt.check("My Secret", scrypt.crypt "My Secret") -- returns true
local b2 = scrypt.check("My Secret", scrypt.crypt "No Secret") -- returns false
```

#### number, number, number scrypt.calibrate(maxmem, maxmemfrac, maxtime)

This function can be used to count `n`, `r`, and `p` configuration values from
`maxmem`, `maxmemfrac` and `maxtime` parameters. These are the defaults for those:

```lua
maxmem     = 1048576
maxmemfrac = 0.5
maxtime    = 0.2
```

The results may change depending on your computer's processing power.

##### Example

```lua
local n,r,p = scrypt.calibrate()
local hash  = scrypt.crypt{
    secret  = "My Secret",
    n = n,
    r = r,
    p = p
}
```

#### number scrypt.memoryuse(n, r, p)

Counts the memory use of scrypt-algorigth with the provided `n`, `r`, and `p`
arguments.

##### Example

```lua
local memoryuse = scrypt.memoryuse(scrypt.calibrate())
```

Default parameters for `n`, `r`, and `p` are:

```lua
n = 32768
r = 8
p = 1
```

## License

`lua-resty-scrypt` uses two clause BSD license.

```
Copyright (c) 2014, Aapo Talvensaari
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
