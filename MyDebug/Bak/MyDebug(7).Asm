.386
.model flat,stdcall
option casemap:none

include windows.inc
include user32.inc
include kernel32.inc 
include msvcrt.inc

includelib msvcrt.lib
includelib kernel32.lib
includelib user32.lib

;�鿴�����
Decode2AsmOpcode proto stdcall pCodeEntry:ptr byte,;��Ҫ����ָ���ַ
                 strAsmCode:ptr byte,;�õ������ָ����Ϣ
                 strOpcode:ptr byte,;������������Ϣ
                 pnCodeSize:ptr dword,;����ָ���
                 nAddress:dword ;���ƫ��
                 
;չʾ��������               
ShowASM proto stdcall :DWORD, :DWORD

;�ȴ�ָ��
WaitCommand proto stdcall :DWORD, :DWORD, :DWORD, :DWORD 
checkReg proto  stdcall :HANDLE, :HANDLE, :DWORD, :DWORD
.data
consoleInHandle dd ? ; ����̨��׼������
zero dd 0h ;��ͨ�ϵ�ļ���
zero1 dd 0h 
bhzero dd 0h ;Ӳ���ϵ�ļ���
bhzero1 dd 0h ;Ӳ���ϵ�鿴����
bmzero dd 0h ;�ڴ�ϵ�����Ӽ���
bmzero1 dd 0h;�ڴ�ϵ�Ĳ鿴������
rfileCount dd 0h ;��ȡ�ű�����
sfileCount dd 0h ;����ű�����
g_pFile dd ? ;�ļ�ָ��
g_pSaveFile dd ? ;�����ļ���ָ��

val dd 010h ;��ֵ16
eight dd 08h ;��ֵ8
g_extract dd ? ;��ȡ��ָ��
g_isTrace db FALSE ;�Ƿ����˸���ָ��
g_isrFile db FALSE ;�Ƿ��ȡ�˽ű�
g_isDebugBpmStep db FALSE;�ڴ�ϵ㵥��
g_isinitSys db  TRUE    ;�Ƿ���ϵͳ��һ�δ������쳣
g_isDebugstep db FALSE ;�����Ƿ񱻴���
g_isbhExecute db FALSE ;Ӳ��ִ�жϵ�
g_isbhVisit db FALSE ;Ӳ�����ʶϵ�
g_isbhWrite db FALSE ;Ӳ��д��ϵ�
g_lpEntryPoint dd ? ;��ڵ��ַ
g_byteOldCode db ? ;��ڵ㱣��ĵ�һ���ֽ�ָ��
g_inputBuff db 128 dup(0) ;����ָ��Ļ�����
g_rfileBuff db 16 dup(0) ;����ӽű�����������
g_asciiBuff db 16 dup(0) ;����ת�����ascii��
g_codesize dd ? ;ָ�����ĳ���
g_Vtable dd 40 dup(0);�洢��ַ�ı�,���洢10���ϵ�
g_Vorderd dd 40 dup(0) ;�洢ָ��ı�
g_bhVtable dd 40 dup(0);�洢Ӳ���ϵ�ı�
g_bmVtable dd 40 dup (0);�洢�ڴ�ϵ��ַ�ı�
g_fileOrderbuff db 128 dup (0);���浼������ָ��
g_traceBuff db 64 dup (0);����һ�и��ٵ�����
g_lpflOldProtect dd ? ;�����ڴ�ϵ�ɵ�����
g_lpflOldProtect1 dd ? ;�ڴ�д��ϵ������
g_traceStartAddr dd ? ;����ָ����ʼ��ַ
g_traceEndAddr dd ? ;����ָ�������ַ
g_pfTrace  dd ? ;�����ļ�ָ��
.const
g_linefeed db 0ah,0dh,0 ;����
g_szFileName db "winmine.exe",0
g_szException db"Exception",0
g_szCreateProcess db"CreateProcess",0
g_szCreateThread db"CreateThread",0
g_szExitProcess db"ExitProcess",0
g_szExitThread db"ExitThread ",0
g_szLoadDll db"LoadDll ",0
g_szUnLoadDll db"UnLoadDll",0
g_format_printf db "command>",0
g_format_scanf db "%127s",0
g_hex_scanf db "%x",0
g_c_sprintf db "%c",0
g_int3 dd 0cch ;�ж�ָ��
g_singleStep db 't',0 ;��������
g_stepThrough db 'p',0 ;��������
g_running db 'g',0 ;����
g_disassembling db 'u',0;�����
g_check_memory db 'd',0 ;�鿴�ڴ�
g_check_reg db 'r',0 ;�鿴�Ĵ���
g_bppoint   db 'bp',0 ;����һ���ڴ�ϵ�
g_inquire_bpoint db 'bpl',0;�鿴һ���ڴ�ϵ�
g_del_bppoint db 'bpc',0 ;ɾ��һ���ڴ�ϵ�
g_hardpoint db 'bh',0 ;����Ӳ���ϵ�
g_check_hardpoint db 'bhl',0 ;�鿴Ӳ���ϵ�
g_del_hardpoint db 'bhc',0 ;ɾ��Ӳ���ϵ�
g_bmpoint db 'bm',0 ;�����ڴ�ϵ�
g_show_bmpoint db 'bml',0 ;�鿴�ڴ�ϵ�
g_paging_bmpoint db 'bmpl',0 ;�鿴��ҳ�ڴ�ϵ��
g_del_bmpoint db 'bmc',0 ;ɾ���ڴ�ϵ�
g_loadScript db 'ls',0 ;����ű�
g_exportScript db 'es',0 ;�����ű�
g_szinput db "%p ",0
g_twohex db "%x:",0
g_dec_scanf db "%d",0;ʮ��������ָ��
g_space db "  ",0
g_fileAddr db "temp.scp",0; ����ű����ļ���
g_filestate db "r+",0;�ļ�����Ϊֻ��
g_fileSave db "save.scp",0;�����ű��ļ�
g_fileTracePath db "trace.txt",0;�����ļ���·��
g_fileSaveState db "w+",0;�ļ�����Ϊֻ��
g_fileTraceState db "a+",0
g_sztrace db "trace",0;����ָ��
g_format_Reg db "EAX = %08x EBX = %08x ECX = %08x EDX = %08x ESI = %08x",0ah,0dh,0
g_format_Reg1 db "EDI = %08x ESP = %08x EBP = %08x FS = %08x ",0ah,0dh,0
g_format_Reg2 db "CS = %08x DS = %08x ES = %08x SS = %08x EIP = %08x",0ah,0dh,0
g_format_Regflag1 db "CF:%d ",0
g_format_Regflag2 db "PF:%d ",0
g_format_Regflag3 db "AF:%d ",0
g_format_Regflag4 db "ZF:%d ",0
g_format_Regflag5 db "SF:%d ",0
g_format_Regflag6 db "TF:%d ",0
g_format_Regflag7 db "IF:%d ",0
g_format_Regflag8 db "DF:%d ",0
g_format_Regflag9 db "OF:%d ",0ah,0dh,0
g_bpl db "���:%d ��ַ:%x ����:%x ���ͣ��û��ϵ�",0ah,0dh,0
g_bhl db "���:%d ��ַ:%x ���ͣ�Ӳ���ϵ�",0ah,0dh,0
g_bh_printf db "Ӳ���ϵ�ִ�У�%x",0ah,0dh,0
g_bm_printf db "���:1 ��ַ:%x ���ȣ�1 ���ͣ��ڴ���ʶϵ�",0ah,0dh,0

g_bmVisit_printf db "�ڴ���ʶϵ�ִ��",0ah,0dh,0
g_bmWrite_printf db "�ڴ�д��ϵ�ִ��",0ah,0dh,0
.code;------------ �����--------------

;չʾ�����
ShowASM proc hProcess:HANDLE,pCodeAddr:LPVOID;�������������̾�������뻺����
    LOCAL   @szCodeBuf[50]:byte ;���뻺����
    LOCAL   @nCodeSize:UINT ;����ĳ���
    LOCAL   @szOpcode[50]:byte;����ָ��
    LOCAL   @szASM[200]:byte;����໺����
    
    jmp NEXT
    
    g_szASMFormat db '%p: %s  %s [%d]',0ah,0dh,0
    
NEXT:
    
    ;��ȡ�ڴ��еĴ���
    invoke ReadProcessMemory,hProcess,pCodeAddr,
        addr @szCodeBuf,sizeof @szCodeBuf,NULL
    
    invoke crt_memset,addr @szASM,0,040h
    
    ;�������� 
    invoke Decode2AsmOpcode,addr @szCodeBuf,addr @szASM,
        addr @szOpcode,addr @nCodeSize,pCodeAddr
    
    ;��ֵ��ǰ���볤�ӳ���
    mov eax,@nCodeSize
    mov g_codesize,eax
    
    ;��ӡ����    
    invoke crt_printf,offset g_szASMFormat,
        pCodeAddr,addr @szOpcode, addr @szASM,@nCodeSize
    
    
    ;����Ϊ�������жϺͼ�¼
    .if g_isTrace
  	 	 mov eax,g_traceStartAddr
   		 mov ebx,g_traceEndAddr
   		 
    	.if pCodeAddr>= eax && pCodeAddr< ebx
    		;д���ļ�
    		invoke crt_fopen,offset g_fileTracePath,offset g_fileTraceState ;���ļ�
    		mov g_pfTrace,eax ;��ֵ�ļ�ָ��
    		
    		invoke crt_fwrite,addr @szASM,1,32,g_pfTrace ;��ȡһ���ֽڵ�����
    		invoke crt_fprintf(fp,"\n");	
			invoke crt_fclose, g_pfTrace;�ͷ��ļ�ָ��
			
    	.endif
    	
    .endif

    
    
    ret

ShowASM endp

;�û�����
WaitCommand proc uses edi ebx ecx hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dbPreCode:byte ;���浱ǰָ���ָ��
	LOCAL @dwPreCode:word ;���浱ǰָ���ָ��
	LOCAL @stepThroughaddr:LPVOID
	LOCAL @runaddr :LPVOID
	LOCAL @checkBuff[16]:byte
	LOCAL @asciiBuff[16]:byte
	LOCAL @decTemp:dword ;ʮ��������
	LOCAL @byte:byte
	LOCAL @bmSize:dword
	LOCAL @temp:dword;�ڴ�ϵ㣬�޸ĵ��ĸ������õ�
	
	
	mov edi,lpContext
	assume edi:ptr CONTEXT

	
	.if !g_isrFile
	invoke crt_printf,offset g_format_printf ;��ʾ
	invoke crt_scanf,offset g_format_scanf,addr g_inputBuff ;����
	mov eax ,sfileCount
	invoke crt_strcpy,addr g_fileOrderbuff[eax], addr g_inputBuff ;��ֵ������
	inc sfileCount
	.endif
	
	;����ָ��
	invoke crt_strcmp, offset g_inputBuff,offset g_sztrace 
	.if eax ==0
		mov g_isTrace,TRUE
		invoke crt_scanf,offset g_hex_scanf,addr g_traceStartAddr ;����ָ����ʼ��ַ
		invoke crt_scanf,offset g_hex_scanf,addr g_traceEndAddr;����ָ�������ַ
		or [edi].regFlag,100h ;��������
		mov g_isDebugstep,TRUE ;������ΪҪ���ֶϵ�����ĵ�������debug����ĵ������Լ��˱���
		ret
	.endif

	
	;�����ű�
	invoke crt_strcmp, offset g_inputBuff,offset g_exportScript 
	.if eax ==0
		invoke crt_fopen,offset g_fileSave,offset g_fileSaveState ;���ļ�
		mov g_pSaveFile,eax ;�ļ�д���ָ��
		
		invoke crt_fwrite,addr g_fileOrderbuff,1,128,g_pSaveFile ;��ȡһ���ֽڵ�����
		
		invoke crt_fclose, g_pSaveFile;�ͷ��ļ�ָ��
		ret
	.endif
	
	
	;����ű�
	invoke crt_strcmp, offset g_inputBuff,offset g_loadScript 
	.if eax ==0
	
		mov g_isrFile,TRUE
		;���ļ��ж�ȡ���ݵ�������
		invoke Sleep,200 ;��ͣһ��
		
		.if	rfileCount==0
			invoke crt_fopen,offset g_fileAddr,offset g_filestate ;���ļ�
			mov g_pFile,eax
		.endif
				
		invoke crt_fread,addr g_rfileBuff,1,1,g_pFile ;��ȡһ���ֽڵ�����

		invoke crt_strcpy,addr g_inputBuff, addr g_rfileBuff ;��ֵ������
					
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext ;�ȴ��û��Ĳ���
		
		invoke crt_strcpy,addr g_inputBuff, addr g_loadScript ;��ֵ������
		
		inc rfileCount ;����++

		mov edx,0   
		mov eax,5;������Ƶ���ָ��ĸ���
		mov ecx,rfileCount
		div ecx
	
		.if eax==0
			invoke crt_fclose, g_pFile;�ͷ��ļ�ָ��
			mov g_isrFile,FALSE
			mov rfileCount,0
		.endif
		
		ret
	.endif
	
	;��������
	invoke crt_strcmp, offset g_inputBuff,offset g_singleStep 
	.if eax ==0 ;˵�������쳣����
		invoke checkReg,hProcess,hThread,lpDebugEv,lpContext
		or [edi].regFlag,100h ;��������
		mov g_isDebugstep,TRUE ;������ΪҪ���ֶϵ�����ĵ�������debug����ĵ������Լ��˱���
		ret
	.else
		mov g_isDebugstep,FALSE
		;�����θ�ֵfalse
	.endif
	
	;ɾ���ڴ�ϵ�
	invoke crt_strcmp, offset g_inputBuff,offset g_del_bmpoint
	.if eax ==0	
		invoke VirtualProtectEx,hProcess,g_bmVtable[0],1,g_lpflOldProtect,addr @temp
		mov g_bmVtable[0],0h
		ret
	.endif
	
	;չʾ�ڴ�ϵ�
	invoke crt_strcmp, offset g_inputBuff,offset g_show_bmpoint
	.if eax ==0
		invoke crt_printf,offset g_bm_printf,g_bmVtable[0]
		ret
	.endif
	
	;�����ڴ�ϵ�
	invoke crt_strcmp, offset g_inputBuff,offset g_bmpoint
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;�����ַ
		;invoke crt_scanf,offset g_dec_scanf,addr @bmSize ;ȷ���ڴ�ϵ�Ĵ�С
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;������д���ڴ�ϵ㻹�Ƕ�ȡ�ڴ�ϵ�
			
		.if @decTemp == 0 ;�����쳣
			
			invoke VirtualProtectEx,hProcess, @runaddr,1,PAGE_NOACCESS,addr g_lpflOldProtect
			
			;�ѵ�ַ�洢���ڴ�ϵ����
			mov eax,@runaddr
			mov ecx,bmzero
			mov g_bmVtable[ecx],eax ;���ӵ�ַ�����,����ע��һ��Ҫ�ֽڶ���
			add bmzero,4 ;��1
			   		
		.endif
		ret
	.endif
	

	;ɾ��Ӳ���ϵ����
	invoke crt_strcmp, offset g_inputBuff,offset g_del_hardpoint
	.if eax ==0
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;����ɾ���ı��
		;����ɾ������Ż�ԭָ��,1 ��ȡ��ַ
		;ָ�ֵΪ��			
		.if @decTemp ==0
			;��ձ�
			mov g_bhVtable[0],0h
			;��ԭ�ϵ�
			mov [edi].iDr0,0h
		    and [edi].iDr7,0fffffffeh
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
    		
		.elseif @decTemp ==1

			mov g_bhVtable[4],0h
			mov [edi].iDr1,0h
		    and [edi].iDr7,0fffffffbh
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
    		
		.elseif @decTemp ==2

			mov g_bhVtable[8],0h
			mov [edi].iDr2,0h
		    and [edi].iDr7,0ffffffefh
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		.endif
		ret
	.endif
	
	;չʾӲ���ϵ��
	invoke crt_strcmp, offset g_inputBuff,offset g_check_hardpoint
	.if eax ==0
	
		mov ebx,0
		.while ebx<0ah ;һ��ѭ��10��
		mov ecx,bhzero1			
		invoke crt_printf,offset g_bhl,ebx,g_bhVtable[ecx]
		
		add bhzero1,4 ;�鿴�ĵ�ַ��4	
		inc ebx
		.endw
			
		;�ڶ�Ӧ��ַ��int3�ϵ��ס����
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		
		ret
	.endif
	
	;����Ӳ���ϵ�
	invoke crt_strcmp, offset g_inputBuff,offset g_hardpoint
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;�����ַ
		
		;invoke GetStdHandle, STD_INPUT_HANDLE;ˢ�»�����
		;mov consoleInHandle,eax
		;invoke FlushConsoleInputBuffer,consoleInHandle
		
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;����ϵ�����
		;-----------------------------------------
		.if @decTemp == 0;ִ�жϵ� 00
		;���öϵ��ַ�����ͣ�����
		mov eax,@runaddr
		mov [edi].iDr0 ,eax
		mov [edi].iDr7 ,1h
		and [edi].iDr7,0fff0ffffh

		;������ͨ�ϵ����Ӳ���ϵ��
		mov eax,@runaddr
		mov ecx,bhzero
		mov g_bhVtable[ecx],eax ;���ӵ�ַ�����,����ע��һ��Ҫ�ֽڶ���
		
		mov g_isbhExecute,TRUE ;��������
		
		add bhzero,4 ;��1
		
		;�ڶ�Ӧ��ַ��int3�ϵ�
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
    	
    	;-------------------------------------------
		.elseif @decTemp == 1;����Ӳ���ϵ� 3
		
		;���öϵ��ַ�����ͣ�����
		mov eax,@runaddr
		mov [edi].iDr1 ,eax
		mov [edi].iDr7 ,4h
		and [edi].iDr7,0ff3fffffh

		;������ͨ�ϵ����Ӳ���ϵ��
		mov eax,@runaddr
		mov ecx,bhzero
		mov g_bhVtable[ecx],eax ;���ӵ�ַ�����,����ע��һ��Ҫ�ֽڶ���
		
		mov g_isbhVisit , TRUE 
		
		add bhzero,4 ;��1
		
		
		;�ڶ�Ӧ��ַ��int3�ϵ�
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		
		;-------------------------------------------
		.elseif @decTemp == 2 ;д��Ӳ���ϵ�   1
		
		;���öϵ��ַ�����ͣ�����
		mov eax,@runaddr
		mov [edi].iDr2 ,eax
		mov [edi].iDr7 ,10h
		and [edi].iDr7,0f1ffffffh

		;������ͨ�ϵ����Ӳ���ϵ��
		mov eax,@runaddr
		mov ecx,bhzero
		mov g_bhVtable[ecx],eax ;���ӵ�ַ�����,����ע��һ��Ҫ�ֽڶ���
		
		mov g_isbhWrite ,TRUE ;Ӳ��д��ϵ�
		add bhzero,4 ;��1
		
		;�ڶ�Ӧ��ַ��int3�ϵ�
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL	
			
		.endif
		
	.endif
	
	
	;ɾ��һ��ϵ�ָ��
	invoke crt_strcmp, offset g_inputBuff,offset g_del_bppoint
	.if eax==0
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;����ɾ���ı��
		;����ɾ������Ż�ԭָ��,1 ��ȡ��ַ
		;ָ�ֵΪ��
				
		.if @decTemp ==0
			invoke WriteProcessMemory,hProcess, g_Vtable[0] ,addr g_Vorderd[0],1,NULL;��ԭָ��
			mov g_Vtable[0],0h
			mov g_Vorderd[0],0h
			
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		.elseif @decTemp ==1
			invoke WriteProcessMemory,hProcess, g_Vtable[4] ,addr g_Vorderd[4],1,NULL;��ԭָ��
			mov g_Vtable[4],0h
			mov g_Vorderd[4],0h
			
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		.elseif @decTemp ==2
			invoke WriteProcessMemory,hProcess, g_Vtable[8] ,addr g_Vorderd[8],1,NULL;��ԭָ��
			mov g_Vtable[8],0h
			mov g_Vorderd[8],0h
			
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		.endif
		
		ret
	.endif
	
	
	;չʾһ���б�
	invoke crt_strcmp, offset g_inputBuff,offset g_inquire_bpoint
	.if eax ==0
	
		mov ebx,0
		.while ebx<0ah ;һ��ѭ��10��
		mov ecx,zero1			
		invoke crt_printf,offset g_bpl,ebx,g_Vtable[ecx], g_Vorderd[ecx]
		
		add zero1,4 ;�鿴�ĵ�ַ��4	
		inc ebx
		.endw
			
		;�ڶ�Ӧ��ַ��int3�ϵ��ס����
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		ret
	.endif

	
	;����һ��ϵ����ӱ�bp
	invoke crt_strcmp, offset g_inputBuff,offset g_bppoint
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;�����ַ
		invoke ReadProcessMemory,hProcess, @runaddr,addr g_extract,1,NULL;��ȡ��ָ��λ��4���ֽڵ�ָ��
		
		;������ͨ�ϵ����ϵ��
		mov eax,@runaddr
		mov ecx,zero
		mov g_Vtable[ecx],eax ;���ӵ�ַ�����,����ע��һ��Ҫ�ֽڶ���
		
		mov eax,g_extract
		mov ecx,zero
		mov g_Vorderd[ecx],eax ;����ָ�ָ�����
		
		add zero,4 ;��1
		
		;�����������û��µ�int3�ϵ�s
		invoke WriteProcessMemory,hProcess,@runaddr,addr g_int3,1,NULL ;���û��Ķϵ�
		
		
		;�ڶ�Ӧ��ַ��int3�ϵ�
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		ret
	.endif
	
	
	;�鿴�Ĵ���
	invoke crt_strcmp, offset g_inputBuff,offset g_check_reg
	.if eax ==0
		invoke checkReg,hProcess,hThread,lpDebugEv,lpContext
		;������һ��int3�ϵ�
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess, [edi].regEip,addr g_int3,1,NULL
    	ret
	.endif
	
	
	;�鿴�ڴ������
	invoke crt_strcmp, offset g_inputBuff,offset g_check_memory
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;����

		;ѭ��8�Σ��ȴ�ӡ��ַ���ڶ�ȡ16�ֽڵ�ַ������%c��ӡ����
		mov ebx,08h
		.while ebx>0
			push ebx
				invoke ReadProcessMemory,hProcess,@runaddr,addr @checkBuff,010h,NULL
					
					;mov ebx,0
					;.while ebx<010h
					
					;invoke crt_sprintf, addr @asciiBuff[ebx],offset g_c_sprintf,byte ptr @checkBuff[ebx]

					;inc ebx
					;.endw
				
				invoke crt_printf,offset g_szinput, @runaddr

					mov ebx,0
					.while ebx<010h
					
					invoke crt_printf,offset g_twohex, byte ptr @checkBuff[ebx]

					inc ebx
					.endw
					
					;invoke crt_printf,offset g_space;�ӿո�

					;mov ebx,0
					;.while ebx<010h
					
					;invoke crt_printf,offset g_c_sprintf, byte ptr @asciiBuff[ebx]

					;inc ebx
					;.endw	
					
					invoke crt_printf,offset g_linefeed;����

			add esp,020h		
			pop ebx
			dec ebx
			add @runaddr,010h
		.endw
		;������һ��int3�ϵ�
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess, [edi].regEip,addr g_int3,1,NULL
	.endif
	
	
	;�鿴�����8��ָ��
	invoke crt_strcmp, offset g_inputBuff,offset g_disassembling
	.if eax ==0
		mov ecx ,7
		.while ecx
			push ecx		
			;�ӵ�ǰָ��鿴�����8��ָ��
			invoke ShowASM,hProcess,[edi].regEip
			inc [edi].regEip
			pop ecx
			dec ecx
		.endw
		;������һ��int3�ϵ�
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess, [edi].regEip,addr g_int3,1,NULL
	.endif
	
	;g����+����ָ��
	invoke crt_strcmp, offset g_inputBuff,offset g_running 
	.if eax ==0 ;ȷ��Ϊgָ��
		;��ʾ�û�����g ������
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;����
		

		;������һ��int3�ϵ�
		invoke ReadProcessMemory,hProcess,@runaddr,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess,@runaddr,addr g_int3,1,NULL
    	ret
	.endif
	

	
	;��������
	invoke crt_strcmp, offset g_inputBuff,offset g_stepThrough 
	.if eax ==0 ;˵��������������
		invoke ReadProcessMemory,hProcess,[edi].regEip,addr @dbPreCode,1,NULL;�����ڴ��жϣ������ȡ�ĵ�һ���ֽ���call,��ֱ��������һ��
			.if @dbPreCode==0e8h
				mov eax,[edi].regEip ;������ǰ��ַ
				add eax,g_codesize;�Ӵ��볤��
				mov @stepThroughaddr,eax
				
  				invoke ReadProcessMemory,hProcess,@stepThroughaddr,addr g_byteOldCode,1,NULL
    			invoke WriteProcessMemory,hProcess,@stepThroughaddr,addr g_int3,1,NULL
    			ret
			.endif
		
			invoke ReadProcessMemory,hProcess,[edi].regEip,addr @dwPreCode,2,NULL
		
			.if @dwPreCode==015ffh
				mov eax,[edi].regEip ;������ǰ��ַ
				add eax,g_codesize;�Ӵ��볤��
				mov @stepThroughaddr,eax
				
  				invoke ReadProcessMemory,hProcess,@stepThroughaddr,addr g_byteOldCode,1,NULL
    			invoke WriteProcessMemory,hProcess,@stepThroughaddr,addr g_int3,1,NULL

				ret	
			.endif
			

		or [edi].regFlag,100h ;��������
		mov g_isDebugstep,TRUE ;������ΪҪ���ֶϵ�����ĵ�������debug����ĵ������Լ��˱���
	.endif
	
	
	
	ret
WaitCommand endp
;�����쳣����
SingleStep proc uses esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED

	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	AND [edi].iDr6 ,0fh ;�����ж���
	.if [edi].iDr6
		invoke crt_printf,offset g_bh_printf,[esi].u.Exception.pExceptionRecord.ExceptionAddress
		;��ԭӲ���ϵ�
		.if g_isbhExecute ;Ӳ��ִ�жϵ�
		mov [edi].iDr0,0h
		and [edi].iDr7,0fffffffeh
		mov g_isbhExecute,FALSE
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
		
		.elseif g_isbhVisit  ;Ӳ�����ʶϵ�
		mov [edi].iDr1,0h
		and [edi].iDr7,0fffffffbh
		mov g_isbhVisit,FALSE
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
		
        .elseif g_isbhWrite  ;Ӳ��д��ϵ�
        mov [edi].iDr2,0h
		and [edi].iDr7,0ffffffefh
		mov g_isbhWrite,FALSE
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
        .endif

	.endif
	
	.if g_isDebugstep ;��������쳣Ϊ��
		invoke ShowASM,hProcess,[esi].u.Exception.pExceptionRecord.ExceptionAddress
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣		
	.endif
	
	;����Ϊ�����ڴ�ϵ�
	.if g_isDebugBpmStep	
		invoke VirtualProtectEx,hProcess,g_bmVtable[0],1,PAGE_NOACCESS,addr g_lpflOldProtect
		mov g_isDebugBpmStep, FALSE;�ڴ�ϵ㵥��
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
	.endif
	
	
	mov eax,@dwContinueStatus
	ret
SingleStep endp

;�ڴ�ϵ��쳣����
AccessViolation proc uses edi esi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwAccessFlag :dword ;��־λ
	LOCAL @dwAccessAddr :dword ;��ַ
	LOCAL @dwContinueStatus:dword
	LOCAL @temp:dword
	
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED 
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	mov eax,[esi].u.Exception.pExceptionRecord.ExceptionInformation[0] ;��ȡ��־λ
	mov @dwAccessFlag,eax
	
	mov ebx,[esi].u.Exception.pExceptionRecord.ExceptionInformation[4] ;��ȡ��־λ
	mov @dwAccessAddr,ebx
	
	
	;�����ж��Ƿ���ͬҳ
	mov edx,g_bmVtable[0]
	and edx,0fffff000h
	and ebx,0fffff000h
	
	.if edx == ebx ;ͬҳ����
		mov eax,g_bmVtable[0]
		.if @dwAccessAddr == eax;hit
		
			.if  @dwAccessFlag==0 ;�����쳣
				invoke crt_printf,offset g_bmVisit_printf
				invoke ShowASM,hProcess,[esi].u.Exception.pExceptionRecord.ExceptionAddress;�����쳣�ĵ�ַ
				invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
				invoke VirtualProtectEx,hProcess,@dwAccessAddr,1,g_lpflOldProtect,addr @temp
				mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
			.endif
			
		.else;����ͬҳ��������
		
			invoke VirtualProtectEx,hProcess,@dwAccessAddr,1,g_lpflOldProtect,addr @temp
			or [edi].regFlag,100h ;�����ϲ�����
			mov g_isDebugBpmStep,TRUE
			mov @dwContinueStatus,DBG_CONTINUE
		
		.endif

	.endif
	
	
	mov eax,@dwContinueStatus
	ret
AccessViolation endp


;�ϵ��쳣����
BreakPoint proc uses esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	mov  eax,[esi].u.Exception.pExceptionRecord.ExceptionAddress 
	
	
	.if eax == g_lpEntryPoint ;������ڵ��ַ
		;��ԭָ��
		invoke WriteProcessMemory,hProcess, g_lpEntryPoint,addr g_byteOldCode,1,NULL
		;��ӡ��ַ
		;invoke crt_printf,offset g_szinput, [edi].regEip
		
		;1 ָ���һ
		dec [edi].regEip
		
		;2 ��ʾ�����
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 ��ʾ�û����в���
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
	
	;�ж��Ƿ�����ͨ�ϵ�1
	.elseif eax == g_Vtable[0] 
		invoke WriteProcessMemory,hProcess, eax,addr g_Vorderd[0],1,NULL	
		;1 ָ���һ
		dec [edi].regEip
		
		;2 ��ʾ�����
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 ��ʾ�û����в���
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
		
	;�ж��Ƿ�����ͨ�ϵ�2	
	.elseif eax == g_Vtable[4]
		invoke WriteProcessMemory,hProcess, eax,addr g_Vorderd[4],1,NULL	
		;1 ָ���һ
		dec [edi].regEip
		
		;2 ��ʾ�����
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 ��ʾ�û����в���
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
		
	;�ж��Ƿ�����ͨ�ϵ�3	
	.elseif eax == g_Vtable[8]
		invoke WriteProcessMemory,hProcess, eax,addr g_Vorderd[8],1,NULL	
		;1 ָ���һ
		dec [edi].regEip
		
		;2 ��ʾ�����
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 ��ʾ�û����в���
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣
			
	.else
		;��ԭָ��
		invoke WriteProcessMemory,hProcess, eax,addr g_byteOldCode,1,NULL
		;��ӡ��ַ
		;invoke crt_printf,offset g_szinput, [edi].regEip
		
		;1 ָ���һ
		dec [edi].regEip
		
		;2 ��ʾ�����
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 ��ʾ�û����в���
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;�Ѿ����������쳣	
	.endif
	
	mov eax,@dwContinueStatus
	ret
BreakPoint endp

;��ʾ�Ĵ������� r
checkReg proc  uses edi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD

	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	invoke crt_printf,offset g_format_Reg,[edi].regEax,[edi].regEbx,[edi].regEcx,[edi].regEdx,[edi].regEsi
	invoke crt_printf,offset g_format_Reg1,[edi].regEdi,[edi].regEsp,[edi].regEbp,[edi].regFs
	invoke crt_printf,offset g_format_Reg2,[edi].regCs,[edi].regDs,[edi].regEs,[edi].regSs,[edi].regEip
	mov eax,[edi].regFlag
	and eax , 0001h ;CF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag1, eax
	
	mov eax,[edi].regFlag
	and eax , 0004h;PF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag2, eax
	
	mov eax,[edi].regFlag
	and eax , 0010h;AF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag3, eax
	
	mov eax,[edi].regFlag
	and eax , 0040h ;ZF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag4, eax
	
	mov eax,[edi].regFlag
	and eax, 0080h ;SF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag5, eax
	
	mov eax,[edi].regFlag
	and eax , 0100h ;TF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag6, eax
	
	mov eax,[edi].regFlag
	and eax , 0200h ;IF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag7, eax
	
	mov eax,[edi].regFlag
	and eax , 0400h ;DF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag8, eax
	
	mov eax,[edi].regFlag
	and eax, 0800h ;OF
	.if eax>0
		mov eax,1
	.endif
	invoke crt_printf,offset g_format_Regflag9, eax
	ret
checkReg endp

;

;�쳣����
OnException proc uses esi  hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	.if [esi].u.Exception.pExceptionRecord.ExceptionCode== EXCEPTION_BREAKPOINT ;���Ϊ�ϵ�
		.if g_isinitSys
			mov g_isinitSys,FALSE
			mov eax,DBG_CONTINUE ;ע���������Ѿ������������ʼ���쳣��
			ret
		.endif
		
		invoke BreakPoint,hProcess,hThread,lpDebugEv,lpContext ;���öϵ㴦������
		mov @dwContinueStatus,eax
		
	.elseif[esi].u.Exception.pExceptionRecord.ExceptionCode== EXCEPTION_SINGLE_STEP ;���Ϊ�����ϵ�
		
		invoke SingleStep,hProcess,hThread,lpDebugEv,lpContext ;���õ�����������
		mov @dwContinueStatus,eax
	
	.elseif[esi].u.Exception.pExceptionRecord.ExceptionCode== EXCEPTION_ACCESS_VIOLATION
		invoke AccessViolation,hProcess,hThread,lpDebugEv,lpContext 
		mov @dwContinueStatus,eax
		
	.endif
	
	mov eax,@dwContinueStatus
	ret

OnException endp


;��������
OnCreateProcess proc uses edi esi  hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	;1 �õ��׵�ַ
 	mov eax,[esi].u.CreateProcessInfo.lpStartAddress
  	mov g_lpEntryPoint,eax
  	
   ;2 ��ȡ�����׵�ַ��һ���ֽ�
  	invoke ReadProcessMemory,hProcess,g_lpEntryPoint,addr g_byteOldCode,1,NULL
  	
   ;3 �ڵ�һ���ֽڴ�д��cc
    invoke WriteProcessMemory,hProcess,g_lpEntryPoint,addr g_int3,1,NULL
    
	mov eax,@dwContinueStatus
	ret

OnCreateProcess endp
;�����߳�
OnCreateThread proc hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	invoke crt_puts,offset g_szCreateThread;3
	mov eax,@dwContinueStatus
	
	ret

OnCreateThread endp
;�˳�����
OnExitProcess proc hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	invoke crt_puts,offset g_szExitProcess;4
	mov eax,@dwContinueStatus
	
	ret

OnExitProcess endp
;�˳��߳�
OnExitThread proc hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	invoke crt_puts,offset g_szExitThread;5
	mov eax,@dwContinueStatus
	
	ret

OnExitThread endp
;����DLL
OnLoadDll proc uses esi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	LOCAL @lpDllName :LPVOID
	LOCAL @szBuff[260]:WORD
	LOCAL @szLen:UINT
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	;1 �õ�debug_Event
	mov esi,lpDebugEv ;���������mov
	assume esi:ptr DEBUG_EVENT
	
	;2 ��ȡdll�����ֵĵ�ַ
	invoke ReadProcessMemory,hProcess,[esi].u.LoadDll.lpImageName,addr @lpDllName,4,NULL
	
	;3 ��ȡdll������
	invoke ReadProcessMemory,hProcess,@lpDllName,addr @szBuff,260*sizeof word,addr @szLen
	
	.if eax ==NULL
		mov eax,@dwContinueStatus
		ret
	.endif
	
	invoke crt__putws,addr @szBuff
	
	mov eax,@dwContinueStatus
	ret

OnLoadDll endp
;ж��DLL
OnUnLoadDll proc hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	invoke crt_puts,offset g_szUnLoadDll;7
	mov eax,@dwContinueStatus
	
	ret

OnUnLoadDll endp



Debug proc
	LOCAL @si:STARTUPINFO
	LOCAL @di:PROCESS_INFORMATION 
	LOCAL @DebugEv:DEBUG_EVENT
	LOCAL @Context:CONTEXT
	LOCAL @dwContinueStatus:dword
	LOCAL @hProcess:HANDLE
	LOCAL @hThread:HANDLE
	
	;-------------------------------------------------------------
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED;Ĭ���������쳣
	
	invoke RtlZeroMemory,addr @si,sizeof STARTUPINFO
	invoke RtlZeroMemory,addr @di,sizeof PROCESS_INFORMATION
	mov @si.cb , sizeof STARTUPINFO
	
	;1 ����ɨ�׽���
	invoke CreateProcess,offset g_szFileName,NULL,NULL,NULL,NULL,
								DEBUG_ONLY_THIS_PROCESS,NULL,NULL,addr @si,addr @di
	;2 �ȴ������¼�
	.While 1
		invoke WaitForDebugEvent,addr @DebugEv,INFINITE
	
	;3 ��ý��̾��
		invoke OpenProcess,PROCESS_ALL_ACCESS,NULL,@DebugEv.dwProcessId
	mov @hProcess,eax
	;4 ����߳̾��
		invoke OpenThread,THREAD_ALL_ACCESS,NULL,@DebugEv.dwThreadId
		mov @hThread,eax
	;5 �õ��߳�������
		mov @Context.ContextFlags,CONTEXT_ALL
		invoke GetThreadContext,@hThread,addr @Context
	;6 ����ѭ���ж�����������
		.if @DebugEv.dwDebugEventCode==EXCEPTION_DEBUG_EVENT;�����쳣�����¼���
			invoke OnException,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
		.elseif @DebugEv.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT;���洴�����̵����¼���
			invoke OnCreateProcess,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
		
		.elseif @DebugEv.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT;���洴���̵߳����¼�
			invoke OnCreateThread,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
		.elseif @DebugEv.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT;�����˳����̵����¼�	
			invoke OnExitProcess,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
		
		.elseif @DebugEv.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT;�����˳��̵߳����¼���	
			invoke OnExitThread,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
			
		.elseif @DebugEv.dwDebugEventCode==UNLOAD_DLL_DEBUG_EVENT;����һ��ж��DLL�����¼�
			invoke OnUnLoadDll,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax	
			
		.elseif @DebugEv.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT;������ض�̬���ӿ⣨DLL�������¼���
			invoke OnLoadDll,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
		.endif
	;7 �ָ���������
		mov @Context.ContextFlags,CONTEXT_ALL
		invoke SetThreadContext,@hThread,addr @Context
	
	
	;8 �رս��̾�����߳̾��	
		invoke CloseHandle,@hProcess
		invoke CloseHandle,@hThread
	
	;9 ���������¼�,��˼���ǵ��Գ����ʱ�����¼���,�㴦������Ҫ����.
		invoke ContinueDebugEvent,@DebugEv.dwProcessId,@DebugEv.dwThreadId,@dwContinueStatus
	.endw
	
	ret

Debug endp
START:
 invoke Debug




end START