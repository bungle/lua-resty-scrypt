local random = require "resty.random"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string

ffi.cdef[[
int crypto_scrypt(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t _r, uint32_t _p, uint8_t * buf, size_t buflen);
int calibrate(size_t maxmem, double maxmemfrac, double maxtime, uint64_t *n, uint32_t *r, uint32_t *p );
]]

local sc = ffi.load("./scryptc.so")

local function hex(str)
    return (str:gsub('.', function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function salt(options)
    if (type(options.salt_size) ~= "number") then
        options.salt_size = 8
    end
    return hex(random.bytes(options.salt_size))
end

local function calibrate(options)
    if (type(options.maxmem) ~= "number") then
        options.maxmem  = 1024 * 1024
    end
    if (type(options.memfrac) ~= "number") then
        options.memfrac = 0.5
    end
    if (type(options.maxtime) ~= "number") then
        options.maxtime = 0.2
    end
    local n = ffi_new("uint64_t[1]", 0)
    local r = ffi_new("uint32_t[1]", 0)
    local p = ffi_new("uint32_t[1]", 0)
    if (sc.calibrate(options.maxmem, options.memfrac, options.maxtime, n, r, p) == 0) then
        return tonumber(n[0]), r[0], p[0]
    end
    return false
end

local function hash(options)
    if (type(options.key_len) ~= "number") then
        options.key_len  = 32
    end
    if (type(options.secret) ~= "string") then
        options.secret = tostring(options.secret)
    end
    if (type(options.n) ~= "number" or type(options.r) ~= "number" or type(options.p) ~= "number") then
        options.n, options.r, options.p = calibrate(options)
    end
    if (type(options.salt) ~= "string") then
        options.salt = salt(options)
    end

    local n = ffi_new("uint64_t[1]", options.n)
    local r = ffi_new("uint32_t[1]", options.r)
    local p = ffi_new("uint32_t[1]", options.p)
    local b = ffi_new("uint8_t[?]",  options.key_len)

    if (sc.crypto_scrypt(options.secret, #options.secret, options.salt, #options.salt, n[0], r[0], p[0], b, options.key_len) == 0) then
        return string.format("%02x$%02x$%02x$", tonumber(n[0]), r[0], p[0]) .. options.salt .. "$" .. hex(ffi_str(b, options.key_len))
    end

    return false
end

return {
    calibrate = calibrate,
    hash      = hash
}
