local t1 = os.time()

local ffi = require 'ffi'
ffi.cdef[[
	char* echo(void);
	unsigned char* encrypt(char *source);
	char* decrypt(char *str);
]]
 
local rsautil = ffi.load'librsautil'

local rsa_str = 'helloworld'
local stren  = ffi.cast("char *", rsa_str);

print(ffi.string(rsautil.echo()))
local bytes = ffi.string(rsautil.encrypt(stren))
print(bytes)



--~ TEST_CASE
local bytes = '67F232483BC834A5D18AB940BFB87CB0BE77031EF5A18C2B9E78754CBA86E711DED5FCF52D8D09D96CC8B507D5E25F663997C55C3053A90D4A7F5088E4AB29C57B5A514D2F387B82406DA4F5A6A141E04C297006E63BFEE349DBE2C2F4FDA960CDFBB59A319BEB44E5D0E30FD5DDBFD5FD9CCCC21BC0E1ABB65BBA9956EF3256'
local str
for i=0, 1000, 1 do
	local oustrbin = ffi.cast("char *", bytes);
	str = ffi.string(rsautil.decrypt(oustrbin))
end
print(str.."\n")
	
local t2 = os.time()
local cha =  t2 - t1
print(cha)