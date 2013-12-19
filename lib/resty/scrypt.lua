local random     = require "resty.random"
local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef
local ffi_new    = ffi.new
local ffi_str    = ffi.string
local ffi_load   = ffi.load
local type       = type
local tonumber   = tonumber
local tostring   = tostring
local str_format = string.format
local str_byte   = string.byte

ffi_cdef[[
int crypto_scrypt(
    const uint8_t *passwd,
    size_t passwdlen,
    const uint8_t *salt,
    size_t saltlen,
    uint64_t N,
    uint32_t _r,
    uint32_t _p,
    uint8_t *buf,
    size_t buflen);
int calibrate(size_t maxmem, double maxmemfrac, double maxtime, uint64_t *n, uint32_t *r, uint32_t *p);
]]

local scrypt = ffi_load("scrypt")

local s = 32
local n = ffi_new("uint64_t[1]", 32768)
local r = ffi_new("uint32_t[1]", 8)
local p = ffi_new("uint32_t[1]", 1)
local b = ffi_new("uint8_t[?]",  s)

local function hex(str)
    return (str:gsub('.', function(c)
        return str_format("%02x", str_byte(c))
    end))
end

local function crypt(opts)
    local secret,salt,saltsize,keysize,n,r,p,b,s = '',nil,8,32,n,r,p,b,s
    if type(opts) ~= "table" then
        secret = tostring(opts)
    else
        if type(opts.secret)  == "string" then secret = opts.secret end
        if type(opts.keysize) == "number" then
            if     opts.keysize < 16  then keysize = 16
            elseif opts.keysize > 512 then keysize = 512
            else                           keysize = opts.keysize end
            if keysize ~= s then
                b,s = ffi_new("uint8_t[?]", keysize), keysize
            end
        end
        if type(opts.n) == "number" then
            if (n[0] ~= opts.n) then n[0] = opts.n end
        end
        if type(opts.r) == "number" then
            if (r[0] ~= opts.r) then r[0] = opts.r end
        end
        if type(opts.p) == "number" then
            if (p[0] ~= opts.p) then p[0] = opts.p end
        end
        if type(opts.salt) == "string" then
            salt = opts.salt
        end
        if type(opts.saltsize) == "number" then
            if opts.saltsize < 8 then
                saltsize = 8
            elseif (opts.saltsize > 32) then
                saltsize = 32
            else
                saltsize = opts.saltsize
            end
        end
    end
    if not salt then salt = hex(random.bytes(saltsize)) end
    if scrypt.crypto_scrypt(
        secret, #secret, salt, #salt, n[0], r[0], p[0], b, keysize) == 0 then
        return str_format("%02x$%02x$%02x$", tonumber(n[0]), r[0], p[0]) ..
                salt .. "$" .. hex(ffi_str(b, keysize))
    end
    return false
end

local function check(secret, hash)
    local opts = {}
    local n, r, p, salt = hash:match(("([^$]*)$"):rep(5))
    opts.secret = secret
    opts.salt = salt
    opts.n = tonumber(n, 16)
    opts.r = tonumber(r, 16)
    opts.p = tonumber(p, 16)
    return crypt(opts) == hash
end

local function calibrate(maxmem, maxmemfrac, maxtime)
    if type(maxmem)     ~= "number" then maxmem = 1048576 end
    if type(maxmemfrac) ~= "number" then maxmemfrac = 0.5 end
    if type(maxtime)    ~= "number" then maxtime    = 0.2 end
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
