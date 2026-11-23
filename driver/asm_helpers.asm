PUBLIC svm_read_cs
PUBLIC svm_read_ds
PUBLIC svm_read_es
PUBLIC svm_read_ss
PUBLIC svm_read_fs
PUBLIC svm_read_gs
PUBLIC svm_read_tr
PUBLIC svm_read_ldtr

.code

svm_read_cs PROC
    mov ax, cs
    ret
svm_read_cs ENDP

svm_read_ds PROC
    mov ax, ds
    ret
svm_read_ds ENDP

svm_read_es PROC
    mov ax, es
    ret
svm_read_es ENDP

svm_read_ss PROC
    mov ax, ss
    ret
svm_read_ss ENDP

svm_read_fs PROC
    mov ax, fs
    ret
svm_read_fs ENDP

svm_read_gs PROC
    mov ax, gs
    ret
svm_read_gs ENDP

svm_read_tr PROC
    str ax
    ret
svm_read_tr ENDP

svm_read_ldtr PROC
    sldt ax
    ret
svm_read_ldtr ENDP

END
