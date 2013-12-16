LUALIB=$(shell lua -e "print(package.path:match(';(.-)?.lua'))")
CLIB=$(shell lua -e "print(package.path:match ';([^;]+lib[^?]+)?')")
LUAINC = '/usr/local/include'

CC= gcc
CFLAGS= $(INCS) $(WARN) -O2 -fPIC $G
WARN=  -pedantic -Wall
INCS= -I$(LUAINC)
MAKESO= $(CC) -shared

OBJS = crypto_scrypt-sse.o memlimit.o scrypt_calibrate.o scryptenc_cpuperf.o sha256.o

all: $(OBJS)
	$(MAKESO) -o scryptc.so $(OBJS)

install:
	cp scryptc.so $(CLIB)
	cp lscrypt.lua $(LUALIB)

uninstall:
	rm $(LUALIB)scrypt.lua
	rm $(CLIB)scryptc.so

clean:
	rm *.o *.so
