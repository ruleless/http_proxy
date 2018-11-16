TARGET:= http_proxy

SRCDIR:= src/
OBJDIR:= .objs/
OUTDIR:=
INSTALL_DIR:= /usr/local/bin
HEADERS:=
LIBS:= -levent -lpthread
INCLUDE:= -I.

CFLAGS:=
CXXFLAGS:=
LDFLAGS:=

include build.mak
