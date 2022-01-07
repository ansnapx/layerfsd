ASM_ERR_LOG = build_errors_asm.log

"$(OBJ_PATH)\$(O)\iaesx64.obj": ..\iaesx64.s
	..\yasm\yasm-1.3.0-win32.exe -f win64 ..\iaesx64.s -o "$@" 2>$(ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\iaesx86_safeseh.obj": ..\iaesx86_safeseh.s
	..\yasm\yasm-1.3.0-win32.exe -f win32 ..\iaesx86_safeseh.s -o "$@" 2>$(ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\aes_amd64.obj": ..\aes_amd64.asm
    ..\yasm\yasm-1.3.0-win32.exe -Xvc -f win64 -o "$@" ..\aes_amd64.asm 2>$(ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\aes_x86_v1.obj": ..\aes_x86_v1.asm
    ..\yasm\yasm-1.3.0-win32.exe -Xvc -f win32 -o "$@" ..\aes_x86_v1.asm 2>$(ASM_ERR_LOG)