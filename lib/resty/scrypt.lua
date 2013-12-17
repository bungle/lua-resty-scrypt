local random = require "resty.random"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string

ffi.cdef[[
int crypto_scrypt(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t _r, uint32_t _p, uint8_t * buf, size_t buflen);
int calibrate(size_t maxmem, double maxmemfrac, double maxtime, uint64_t *n, uint32_t *r, uint32_t *p);
]]

local scrypt = ffi.load("/usr/local/openresty/lualib/scrypt.so")

local function hex(str)
    return (str:gsub('.', function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function crypt(options)
    if type(options) ~= "table" then
        options = { secret = tostring(options) }
    elseif (type(options.secret) ~= "string") then
        options.secret = tostring(options.secret)
    end
    if type(options.keysize) ~= "number" then
        options.keysize  = 32
    else
        if options.keysize < 16 then
            options.keysize = 16
        elseif (options.keysize > 512) then
            options.keysize = 512
        end
    end
    if type(options.n) ~= "number" then
        options.n = 32768
    end
    if type(options.r) ~= "number" then
        options.r = 8
    end
    if type(options.p) ~= "number" then
        options.p = 1
    end
    if type(options.salt) ~= "string" then
        if type(options.saltsize) ~= "number" then
            options.saltsize = 8
        else
            if options.saltsize < 8 then
                options.saltsize = 8
            elseif (options.saltsize > 32) then
                options.saltsize = 32
            end
        end
        options.salt = hex(random.bytes(options.saltsize))
    end
    local n = ffi_new("uint64_t[1]", options.n)
    local r = ffi_new("uint32_t[1]", options.r)
    local p = ffi_new("uint32_t[1]", options.p)
    local b = ffi_new("uint8_t[?]",  options.keysize)
    if (scrypt.crypto_scrypt(options.secret, #options.secret, options.salt, #options.salt, n[0], r[0], p[0], b, options.keysize) == 0) then
        return string.format("%02x$%02x$%02x$", tonumber(n[0]), r[0], p[0]) .. options.salt .. "$" .. hex(ffi_str(b, options.keysize))
    end
    return false
end

local function check(secret, hash)
    local options = {}
    local n, r, p, salt = hash:match(("([^$]*)$"):rep(5))
    options.secret = secret
    options.salt = salt
    options.n = tonumber(n, 16)
    options.r = tonumber(r, 16)
    options.p = tonumber(p, 16)
    return crypt(options) == hash
end

local function calibrate(maxmem, maxmemfrac, maxtime)
    if type(maxmem) ~= "number" then
        maxmem = 1048576
    end
    if type(maxmemfrac) ~= "number" then
        maxmemfrac = 0.5
    end
    if type(maxtime) ~= "number" then
        maxtime = 0.2
    end
    local n = ffi_new("uint64_t[1]", 0)
    local r = ffi_new("uint32_t[1]", 0)
    local p = ffi_new("uint32_t[1]", 0)
    if (scrypt.calibrate(maxmem, maxmemfrac, maxtime, n, r, p) == 0) then
        return tonumber(n[0]), r[0], p[0]
    end
    return false
end

local function memoryuse(n, r, p)
    return 128 * r * p + 256 * r + 128 * r * n;
end

return {
    crypt     = crypt,
    check     = check,
    calibrate = calibrate,
    memoryuse = memoryuse
}
