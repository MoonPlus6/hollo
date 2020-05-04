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

;查看反汇编
Decode2AsmOpcode proto stdcall pCodeEntry:ptr byte,;需要解析指令地址
                 strAsmCode:ptr byte,;得到反汇编指令信息
                 strOpcode:ptr byte,;解析机器码信息
                 pnCodeSize:ptr dword,;解析指令长度
                 nAddress:dword ;相对偏移
                 
;展示反汇编代码               
ShowASM proto stdcall :DWORD, :DWORD

;等待指令
WaitCommand proto stdcall :DWORD, :DWORD, :DWORD, :DWORD 
checkReg proto  stdcall :HANDLE, :HANDLE, :DWORD, :DWORD
.data
consoleInHandle dd ? ; 控制台标准输入句柄
zero dd 0h ;普通断点的计数
zero1 dd 0h 
bhzero dd 0h ;硬件断点的计数
bhzero1 dd 0h ;硬件断点查看计数
bmzero dd 0h ;内存断点的增加计数
bmzero1 dd 0h;内存断点的查看表计数
rfileCount dd 0h ;读取脚本计数
sfileCount dd 0h ;保存脚本计数
g_pFile dd ? ;文件指针
g_pSaveFile dd ? ;导出文件的指针

val dd 010h ;定值16
eight dd 08h ;定值8
g_extract dd ? ;提取的指令
g_isTrace db FALSE ;是否开启了跟踪指令
g_isrFile db FALSE ;是否读取了脚本
g_isDebugBpmStep db FALSE;内存断点单步
g_isinitSys db  TRUE    ;是否是系统第一次触发的异常
g_isDebugstep db FALSE ;单步是否被触发
g_isbhExecute db FALSE ;硬件执行断点
g_isbhVisit db FALSE ;硬件访问断点
g_isbhWrite db FALSE ;硬件写入断点
g_lpEntryPoint dd ? ;入口点地址
g_byteOldCode db ? ;入口点保存的第一个字节指令
g_inputBuff db 128 dup(0) ;输入指令的缓冲区
g_rfileBuff db 16 dup(0) ;保存从脚本读出的内容
g_asciiBuff db 16 dup(0) ;保存转换完的ascii码
g_codesize dd ? ;指令代码的长度
g_Vtable dd 40 dup(0);存储地址的表,最多存储10个断点
g_Vorderd dd 40 dup(0) ;存储指令的表
g_bhVtable dd 40 dup(0);存储硬件断点的表
g_bmVtable dd 40 dup (0);存储内存断点地址的表
g_fileOrderbuff db 128 dup (0);保存导出表的指令
g_traceBuff db 64 dup (0);保存一行跟踪的数据
g_lpflOldProtect dd ? ;保存内存断点旧的属性
g_lpflOldProtect1 dd ? ;内存写入断点旧属性
g_traceStartAddr dd ? ;跟踪指令起始地址
g_traceEndAddr dd ? ;跟踪指令结束地址
g_pfTrace  dd ? ;跟踪文件指针
.const
g_linefeed db 0ah,0dh,0 ;换行
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
g_int3 dd 0cch ;中断指令
g_singleStep db 't',0 ;单步步入
g_stepThrough db 'p',0 ;单步步过
g_running db 'g',0 ;运行
g_disassembling db 'u',0;反汇编
g_check_memory db 'd',0 ;查看内存
g_check_reg db 'r',0 ;查看寄存器
g_bppoint   db 'bp',0 ;设置一般内存断点
g_inquire_bpoint db 'bpl',0;查看一般内存断点
g_del_bppoint db 'bpc',0 ;删除一般内存断点
g_hardpoint db 'bh',0 ;添加硬件断点
g_check_hardpoint db 'bhl',0 ;查看硬件断点
g_del_hardpoint db 'bhc',0 ;删除硬件断点
g_bmpoint db 'bm',0 ;添加内存断点
g_show_bmpoint db 'bml',0 ;查看内存断点
g_paging_bmpoint db 'bmpl',0 ;查看分页内存断点表
g_del_bmpoint db 'bmc',0 ;删除内存断点
g_loadScript db 'ls',0 ;导入脚本
g_exportScript db 'es',0 ;导出脚本
g_szinput db "%p ",0
g_twohex db "%x:",0
g_dec_scanf db "%d",0;十进制输入指令
g_space db "  ",0
g_fileAddr db "temp.scp",0; 导入脚本的文件名
g_filestate db "r+",0;文件属性为只读
g_fileSave db "save.scp",0;导出脚本文件
g_fileTracePath db "trace.txt",0;跟踪文件的路径
g_fileSaveState db "w+",0;文件属性为只读
g_fileTraceState db "a+",0
g_sztrace db "trace",0;跟踪指令
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
g_bpl db "序号:%d 地址:%x 代码:%x 类型：用户断点",0ah,0dh,0
g_bhl db "序号:%d 地址:%x 类型：硬件断点",0ah,0dh,0
g_bh_printf db "硬件断点执行：%x",0ah,0dh,0
g_bm_printf db "序号:1 地址:%x 长度：1 类型：内存访问断点",0ah,0dh,0

g_bmVisit_printf db "内存访问断点执行",0ah,0dh,0
g_bmWrite_printf db "内存写入断点执行",0ah,0dh,0
.code;------------ 代码段--------------

;展示反汇编
ShowASM proc hProcess:HANDLE,pCodeAddr:LPVOID;两个参数，进程句柄，代码缓冲区
    LOCAL   @szCodeBuf[50]:byte ;代码缓冲区
    LOCAL   @nCodeSize:UINT ;代码的长度
    LOCAL   @szOpcode[50]:byte;机器指令
    LOCAL   @szASM[200]:byte;反汇编缓冲区
    
    jmp NEXT
    
    g_szASMFormat db '%p: %s  %s [%d]',0ah,0dh,0
    
NEXT:
    
    ;读取内存中的代码
    invoke ReadProcessMemory,hProcess,pCodeAddr,
        addr @szCodeBuf,sizeof @szCodeBuf,NULL
    
    invoke crt_memset,addr @szASM,0,040h
    
    ;反汇编出来 
    invoke Decode2AsmOpcode,addr @szCodeBuf,addr @szASM,
        addr @szOpcode,addr @nCodeSize,pCodeAddr
    
    ;赋值当前代码长队长度
    mov eax,@nCodeSize
    mov g_codesize,eax
    
    ;打印出来    
    invoke crt_printf,offset g_szASMFormat,
        pCodeAddr,addr @szOpcode, addr @szASM,@nCodeSize
    
    
    ;这里为跟踪做判断和记录
    .if g_isTrace
  	 	 mov eax,g_traceStartAddr
   		 mov ebx,g_traceEndAddr
   		 
    	.if pCodeAddr>= eax && pCodeAddr< ebx
    		;写入文件
    		invoke crt_fopen,offset g_fileTracePath,offset g_fileTraceState ;打开文件
    		mov g_pfTrace,eax ;赋值文件指令
    		
    		invoke crt_fwrite,addr @szASM,1,32,g_pfTrace ;读取一个字节的内容
    		invoke crt_fprintf,g_pfTrace,"\n");	
			invoke crt_fclose, g_pfTrace;释放文件指针
			
    	.endif
    	
    .endif

    
    
    ret

ShowASM endp

;用户操作
WaitCommand proc uses edi ebx ecx hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dbPreCode:byte ;保存当前指向的指令
	LOCAL @dwPreCode:word ;保存当前指向的指令
	LOCAL @stepThroughaddr:LPVOID
	LOCAL @runaddr :LPVOID
	LOCAL @checkBuff[16]:byte
	LOCAL @asciiBuff[16]:byte
	LOCAL @decTemp:dword ;十进制输入
	LOCAL @byte:byte
	LOCAL @bmSize:dword
	LOCAL @temp:dword;内存断点，修改第四个参数用的
	
	
	mov edi,lpContext
	assume edi:ptr CONTEXT

	
	.if !g_isrFile
	invoke crt_printf,offset g_format_printf ;提示
	invoke crt_scanf,offset g_format_scanf,addr g_inputBuff ;输入
	mov eax ,sfileCount
	invoke crt_strcpy,addr g_fileOrderbuff[eax], addr g_inputBuff ;赋值缓冲区
	inc sfileCount
	.endif
	
	;跟踪指令
	invoke crt_strcmp, offset g_inputBuff,offset g_sztrace 
	.if eax ==0
		mov g_isTrace,TRUE
		invoke crt_scanf,offset g_hex_scanf,addr g_traceStartAddr ;跟踪指令起始地址
		invoke crt_scanf,offset g_hex_scanf,addr g_traceEndAddr;跟踪指令结束地址
		or [edi].regFlag,100h ;触发单步
		mov g_isDebugstep,TRUE ;这里因为要区分断点引起的单步，和debug引起的单步所以加了变量
		ret
	.endif

	
	;导出脚本
	invoke crt_strcmp, offset g_inputBuff,offset g_exportScript 
	.if eax ==0
		invoke crt_fopen,offset g_fileSave,offset g_fileSaveState ;打开文件
		mov g_pSaveFile,eax ;文件写入的指针
		
		invoke crt_fwrite,addr g_fileOrderbuff,1,128,g_pSaveFile ;读取一个字节的内容
		
		invoke crt_fclose, g_pSaveFile;释放文件指针
		ret
	.endif
	
	
	;导入脚本
	invoke crt_strcmp, offset g_inputBuff,offset g_loadScript 
	.if eax ==0
	
		mov g_isrFile,TRUE
		;从文件中读取内容到缓冲区
		invoke Sleep,200 ;暂停一下
		
		.if	rfileCount==0
			invoke crt_fopen,offset g_fileAddr,offset g_filestate ;打开文件
			mov g_pFile,eax
		.endif
				
		invoke crt_fread,addr g_rfileBuff,1,1,g_pFile ;读取一个字节的内容

		invoke crt_strcpy,addr g_inputBuff, addr g_rfileBuff ;赋值缓冲区
					
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext ;等待用户的操作
		
		invoke crt_strcpy,addr g_inputBuff, addr g_loadScript ;赋值缓冲区
		
		inc rfileCount ;计数++

		mov edx,0   
		mov eax,5;这里控制导入指令的个数
		mov ecx,rfileCount
		div ecx
	
		.if eax==0
			invoke crt_fclose, g_pFile;释放文件指针
			mov g_isrFile,FALSE
			mov rfileCount,0
		.endif
		
		ret
	.endif
	
	;单步步入
	invoke crt_strcmp, offset g_inputBuff,offset g_singleStep 
	.if eax ==0 ;说明单步异常触发
		invoke checkReg,hProcess,hThread,lpDebugEv,lpContext
		or [edi].regFlag,100h ;触发单步
		mov g_isDebugstep,TRUE ;这里因为要区分断点引起的单步，和debug引起的单步所以加了变量
		ret
	.else
		mov g_isDebugstep,FALSE
		;这里多次赋值false
	.endif
	
	;删除内存断点
	invoke crt_strcmp, offset g_inputBuff,offset g_del_bmpoint
	.if eax ==0	
		invoke VirtualProtectEx,hProcess,g_bmVtable[0],1,g_lpflOldProtect,addr @temp
		mov g_bmVtable[0],0h
		ret
	.endif
	
	;展示内存断点
	invoke crt_strcmp, offset g_inputBuff,offset g_show_bmpoint
	.if eax ==0
		invoke crt_printf,offset g_bm_printf,g_bmVtable[0]
		ret
	.endif
	
	;添加内存断点
	invoke crt_strcmp, offset g_inputBuff,offset g_bmpoint
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;输入地址
		;invoke crt_scanf,offset g_dec_scanf,addr @bmSize ;确定内存断点的大小
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;输入是写入内存断点还是读取内存断点
			
		.if @decTemp == 0 ;访问异常
			
			invoke VirtualProtectEx,hProcess, @runaddr,1,PAGE_NOACCESS,addr g_lpflOldProtect
			
			;把地址存储到内存断点表中
			mov eax,@runaddr
			mov ecx,bmzero
			mov g_bmVtable[ecx],eax ;添加地址进入表,这里注意一定要字节对齐
			add bmzero,4 ;加1
			   		
		.endif
		ret
	.endif
	

	;删除硬件断点表项
	invoke crt_strcmp, offset g_inputBuff,offset g_del_hardpoint
	.if eax ==0
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;输入删除的编号
		;根据删除的序号还原指令,1 读取地址
		;指令赋值为空			
		.if @decTemp ==0
			;清空表
			mov g_bhVtable[0],0h
			;还原断点
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
	
	;展示硬件断点表
	invoke crt_strcmp, offset g_inputBuff,offset g_check_hardpoint
	.if eax ==0
	
		mov ebx,0
		.while ebx<0ah ;一共循环10次
		mov ecx,bhzero1			
		invoke crt_printf,offset g_bhl,ebx,g_bhVtable[ecx]
		
		add bhzero1,4 ;查看的地址加4	
		inc ebx
		.endw
			
		;在对应地址下int3断点断住程序
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		
		ret
	.endif
	
	;添加硬件断点
	invoke crt_strcmp, offset g_inputBuff,offset g_hardpoint
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;输入地址
		
		;invoke GetStdHandle, STD_INPUT_HANDLE;刷新缓冲区
		;mov consoleInHandle,eax
		;invoke FlushConsoleInputBuffer,consoleInHandle
		
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;输入断点类型
		;-----------------------------------------
		.if @decTemp == 0;执行断点 00
		;设置断点地址，类型，长度
		mov eax,@runaddr
		mov [edi].iDr0 ,eax
		mov [edi].iDr7 ,1h
		and [edi].iDr7,0fff0ffffh

		;添加普通断点进入硬件断点表
		mov eax,@runaddr
		mov ecx,bhzero
		mov g_bhVtable[ecx],eax ;添加地址进入表,这里注意一定要字节对齐
		
		mov g_isbhExecute,TRUE ;设置属性
		
		add bhzero,4 ;加1
		
		;在对应地址下int3断点
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
    	
    	;-------------------------------------------
		.elseif @decTemp == 1;访问硬件断点 3
		
		;设置断点地址，类型，长度
		mov eax,@runaddr
		mov [edi].iDr1 ,eax
		mov [edi].iDr7 ,4h
		and [edi].iDr7,0ff3fffffh

		;添加普通断点进入硬件断点表
		mov eax,@runaddr
		mov ecx,bhzero
		mov g_bhVtable[ecx],eax ;添加地址进入表,这里注意一定要字节对齐
		
		mov g_isbhVisit , TRUE 
		
		add bhzero,4 ;加1
		
		
		;在对应地址下int3断点
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		
		;-------------------------------------------
		.elseif @decTemp == 2 ;写入硬件断点   1
		
		;设置断点地址，类型，长度
		mov eax,@runaddr
		mov [edi].iDr2 ,eax
		mov [edi].iDr7 ,10h
		and [edi].iDr7,0f1ffffffh

		;添加普通断点进入硬件断点表
		mov eax,@runaddr
		mov ecx,bhzero
		mov g_bhVtable[ecx],eax ;添加地址进入表,这里注意一定要字节对齐
		
		mov g_isbhWrite ,TRUE ;硬件写入断点
		add bhzero,4 ;加1
		
		;在对应地址下int3断点
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL	
			
		.endif
		
	.endif
	
	
	;删除一般断点指令
	invoke crt_strcmp, offset g_inputBuff,offset g_del_bppoint
	.if eax==0
		invoke crt_scanf,offset g_dec_scanf,addr @decTemp ;输入删除的编号
		;根据删除的序号还原指令,1 读取地址
		;指令赋值为空
				
		.if @decTemp ==0
			invoke WriteProcessMemory,hProcess, g_Vtable[0] ,addr g_Vorderd[0],1,NULL;还原指令
			mov g_Vtable[0],0h
			mov g_Vorderd[0],0h
			
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		.elseif @decTemp ==1
			invoke WriteProcessMemory,hProcess, g_Vtable[4] ,addr g_Vorderd[4],1,NULL;还原指令
			mov g_Vtable[4],0h
			mov g_Vorderd[4],0h
			
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		.elseif @decTemp ==2
			invoke WriteProcessMemory,hProcess, g_Vtable[8] ,addr g_Vorderd[8],1,NULL;还原指令
			mov g_Vtable[8],0h
			mov g_Vorderd[8],0h
			
			invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    		invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		.endif
		
		ret
	.endif
	
	
	;展示一般列表
	invoke crt_strcmp, offset g_inputBuff,offset g_inquire_bpoint
	.if eax ==0
	
		mov ebx,0
		.while ebx<0ah ;一共循环10次
		mov ecx,zero1			
		invoke crt_printf,offset g_bpl,ebx,g_Vtable[ecx], g_Vorderd[ecx]
		
		add zero1,4 ;查看的地址加4	
		inc ebx
		.endw
			
		;在对应地址下int3断点断住程序
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		ret
	.endif

	
	;设置一般断点添加表bp
	invoke crt_strcmp, offset g_inputBuff,offset g_bppoint
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;输入地址
		invoke ReadProcessMemory,hProcess, @runaddr,addr g_extract,1,NULL;读取到指定位置4个字节的指令
		
		;添加普通断点进入断点表
		mov eax,@runaddr
		mov ecx,zero
		mov g_Vtable[ecx],eax ;添加地址进入表,这里注意一定要字节对齐
		
		mov eax,g_extract
		mov ecx,zero
		mov g_Vorderd[ecx],eax ;添加指令到指令表中
		
		add zero,4 ;加1
		
		;在这里添加用户下的int3断点s
		invoke WriteProcessMemory,hProcess,@runaddr,addr g_int3,1,NULL ;下用户的断点
		
		
		;在对应地址下int3断点
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL;
    	invoke WriteProcessMemory,hProcess,[edi].regEip,addr g_int3,1,NULL
		ret
	.endif
	
	
	;查看寄存器
	invoke crt_strcmp, offset g_inputBuff,offset g_check_reg
	.if eax ==0
		invoke checkReg,hProcess,hThread,lpDebugEv,lpContext
		;并且下一个int3断点
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess, [edi].regEip,addr g_int3,1,NULL
    	ret
	.endif
	
	
	;查看内存带参数
	invoke crt_strcmp, offset g_inputBuff,offset g_check_memory
	.if eax ==0
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;输入

		;循环8次，先打印地址，在读取16字节地址，在用%c打印出来
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
					
					;invoke crt_printf,offset g_space;加空格

					;mov ebx,0
					;.while ebx<010h
					
					;invoke crt_printf,offset g_c_sprintf, byte ptr @asciiBuff[ebx]

					;inc ebx
					;.endw	
					
					invoke crt_printf,offset g_linefeed;换行

			add esp,020h		
			pop ebx
			dec ebx
			add @runaddr,010h
		.endw
		;并且下一个int3断点
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess, [edi].regEip,addr g_int3,1,NULL
	.endif
	
	
	;查看反汇编8条指令
	invoke crt_strcmp, offset g_inputBuff,offset g_disassembling
	.if eax ==0
		mov ecx ,7
		.while ecx
			push ecx		
			;从当前指令处查看反汇编8条指令
			invoke ShowASM,hProcess,[edi].regEip
			inc [edi].regEip
			pop ecx
			dec ecx
		.endw
		;并且下一个int3断点
		invoke ReadProcessMemory,hProcess, [edi].regEip,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess, [edi].regEip,addr g_int3,1,NULL
	.endif
	
	;g运行+参数指令
	invoke crt_strcmp, offset g_inputBuff,offset g_running 
	.if eax ==0 ;确定为g指令
		;提示用户输入g 到哪里
		invoke crt_scanf,offset g_hex_scanf,addr @runaddr ;输入
		

		;并且下一个int3断点
		invoke ReadProcessMemory,hProcess,@runaddr,addr g_byteOldCode,1,NULL
    	invoke WriteProcessMemory,hProcess,@runaddr,addr g_int3,1,NULL
    	ret
	.endif
	

	
	;单步步过
	invoke crt_strcmp, offset g_inputBuff,offset g_stepThrough 
	.if eax ==0 ;说明单步步过触发
		invoke ReadProcessMemory,hProcess,[edi].regEip,addr @dbPreCode,1,NULL;这里在次判断，如果读取的第一个字节是call,就直接跳到下一条
			.if @dbPreCode==0e8h
				mov eax,[edi].regEip ;读出当前地址
				add eax,g_codesize;加代码长度
				mov @stepThroughaddr,eax
				
  				invoke ReadProcessMemory,hProcess,@stepThroughaddr,addr g_byteOldCode,1,NULL
    			invoke WriteProcessMemory,hProcess,@stepThroughaddr,addr g_int3,1,NULL
    			ret
			.endif
		
			invoke ReadProcessMemory,hProcess,[edi].regEip,addr @dwPreCode,2,NULL
		
			.if @dwPreCode==015ffh
				mov eax,[edi].regEip ;读出当前地址
				add eax,g_codesize;加代码长度
				mov @stepThroughaddr,eax
				
  				invoke ReadProcessMemory,hProcess,@stepThroughaddr,addr g_byteOldCode,1,NULL
    			invoke WriteProcessMemory,hProcess,@stepThroughaddr,addr g_int3,1,NULL

				ret	
			.endif
			

		or [edi].regFlag,100h ;触发单步
		mov g_isDebugstep,TRUE ;这里因为要区分断点引起的单步，和debug引起的单步所以加了变量
	.endif
	
	
	
	ret
WaitCommand endp
;单步异常处理
SingleStep proc uses esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED

	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	AND [edi].iDr6 ,0fh ;这里判断是
	.if [edi].iDr6
		invoke crt_printf,offset g_bh_printf,[esi].u.Exception.pExceptionRecord.ExceptionAddress
		;还原硬件断点
		.if g_isbhExecute ;硬件执行断点
		mov [edi].iDr0,0h
		and [edi].iDr7,0fffffffeh
		mov g_isbhExecute,FALSE
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
		
		.elseif g_isbhVisit  ;硬件访问断点
		mov [edi].iDr1,0h
		and [edi].iDr7,0fffffffbh
		mov g_isbhVisit,FALSE
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
		
        .elseif g_isbhWrite  ;硬件写入断点
        mov [edi].iDr2,0h
		and [edi].iDr7,0ffffffefh
		mov g_isbhWrite,FALSE
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
        .endif

	.endif
	
	.if g_isDebugstep ;如果单步异常为真
		invoke ShowASM,hProcess,[esi].u.Exception.pExceptionRecord.ExceptionAddress
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常		
	.endif
	
	;这里为处理内存断点
	.if g_isDebugBpmStep	
		invoke VirtualProtectEx,hProcess,g_bmVtable[0],1,PAGE_NOACCESS,addr g_lpflOldProtect
		mov g_isDebugBpmStep, FALSE;内存断点单步
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
	.endif
	
	
	mov eax,@dwContinueStatus
	ret
SingleStep endp

;内存断点异常处理
AccessViolation proc uses edi esi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwAccessFlag :dword ;标志位
	LOCAL @dwAccessAddr :dword ;地址
	LOCAL @dwContinueStatus:dword
	LOCAL @temp:dword
	
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED 
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	mov eax,[esi].u.Exception.pExceptionRecord.ExceptionInformation[0] ;获取标志位
	mov @dwAccessFlag,eax
	
	mov ebx,[esi].u.Exception.pExceptionRecord.ExceptionInformation[4] ;获取标志位
	mov @dwAccessAddr,ebx
	
	
	;这里判断是否在同页
	mov edx,g_bmVtable[0]
	and edx,0fffff000h
	and ebx,0fffff000h
	
	.if edx == ebx ;同页命中
		mov eax,g_bmVtable[0]
		.if @dwAccessAddr == eax;hit
		
			.if  @dwAccessFlag==0 ;访问异常
				invoke crt_printf,offset g_bmVisit_printf
				invoke ShowASM,hProcess,[esi].u.Exception.pExceptionRecord.ExceptionAddress;发生异常的地址
				invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
				invoke VirtualProtectEx,hProcess,@dwAccessAddr,1,g_lpflOldProtect,addr @temp
				mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
			.endif
			
		.else;命中同页其他数据
		
			invoke VirtualProtectEx,hProcess,@dwAccessAddr,1,g_lpflOldProtect,addr @temp
			or [edi].regFlag,100h ;触发断步程序
			mov g_isDebugBpmStep,TRUE
			mov @dwContinueStatus,DBG_CONTINUE
		
		.endif

	.endif
	
	
	mov eax,@dwContinueStatus
	ret
AccessViolation endp


;断点异常处理
BreakPoint proc uses esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	mov  eax,[esi].u.Exception.pExceptionRecord.ExceptionAddress 
	
	
	.if eax == g_lpEntryPoint ;等于入口点地址
		;复原指令
		invoke WriteProcessMemory,hProcess, g_lpEntryPoint,addr g_byteOldCode,1,NULL
		;打印地址
		;invoke crt_printf,offset g_szinput, [edi].regEip
		
		;1 指令减一
		dec [edi].regEip
		
		;2 显示反汇编
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 提示用户进行操作
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
	
	;判断是否是普通断点1
	.elseif eax == g_Vtable[0] 
		invoke WriteProcessMemory,hProcess, eax,addr g_Vorderd[0],1,NULL	
		;1 指令减一
		dec [edi].regEip
		
		;2 显示反汇编
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 提示用户进行操作
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
		
	;判断是否是普通断点2	
	.elseif eax == g_Vtable[4]
		invoke WriteProcessMemory,hProcess, eax,addr g_Vorderd[4],1,NULL	
		;1 指令减一
		dec [edi].regEip
		
		;2 显示反汇编
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 提示用户进行操作
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
		
	;判断是否是普通断点3	
	.elseif eax == g_Vtable[8]
		invoke WriteProcessMemory,hProcess, eax,addr g_Vorderd[8],1,NULL	
		;1 指令减一
		dec [edi].regEip
		
		;2 显示反汇编
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 提示用户进行操作
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常
			
	.else
		;复原指令
		invoke WriteProcessMemory,hProcess, eax,addr g_byteOldCode,1,NULL
		;打印地址
		;invoke crt_printf,offset g_szinput, [edi].regEip
		
		;1 指令减一
		dec [edi].regEip
		
		;2 显示反汇编
		invoke ShowASM,hProcess,[edi].regEip
		
		;3 提示用户进行操作
		invoke WaitCommand,hProcess,hThread,lpDebugEv,lpContext
		
		mov @dwContinueStatus,DBG_CONTINUE ;已经处理掉了异常	
	.endif
	
	mov eax,@dwContinueStatus
	ret
BreakPoint endp

;显示寄存器环境 r
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

;异常调试
OnException proc uses esi  hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	.if [esi].u.Exception.pExceptionRecord.ExceptionCode== EXCEPTION_BREAKPOINT ;如果为断点
		.if g_isinitSys
			mov g_isinitSys,FALSE
			mov eax,DBG_CONTINUE ;注意这里是已经处理掉这个初始的异常了
			ret
		.endif
		
		invoke BreakPoint,hProcess,hThread,lpDebugEv,lpContext ;调用断点处理函数
		mov @dwContinueStatus,eax
		
	.elseif[esi].u.Exception.pExceptionRecord.ExceptionCode== EXCEPTION_SINGLE_STEP ;如果为单步断点
		
		invoke SingleStep,hProcess,hThread,lpDebugEv,lpContext ;调用单步处理函数
		mov @dwContinueStatus,eax
	
	.elseif[esi].u.Exception.pExceptionRecord.ExceptionCode== EXCEPTION_ACCESS_VIOLATION
		invoke AccessViolation,hProcess,hThread,lpDebugEv,lpContext 
		mov @dwContinueStatus,eax
		
	.endif
	
	mov eax,@dwContinueStatus
	ret

OnException endp


;创建进程
OnCreateProcess proc uses edi esi  hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	mov esi,lpDebugEv
	assume esi:ptr DEBUG_EVENT
	
	mov edi,lpContext
	assume edi:ptr CONTEXT
	
	;1 拿到首地址
 	mov eax,[esi].u.CreateProcessInfo.lpStartAddress
  	mov g_lpEntryPoint,eax
  	
   ;2 读取保存首地址第一个字节
  	invoke ReadProcessMemory,hProcess,g_lpEntryPoint,addr g_byteOldCode,1,NULL
  	
   ;3 在第一个字节处写入cc
    invoke WriteProcessMemory,hProcess,g_lpEntryPoint,addr g_int3,1,NULL
    
	mov eax,@dwContinueStatus
	ret

OnCreateProcess endp
;创建线程
OnCreateThread proc hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	invoke crt_puts,offset g_szCreateThread;3
	mov eax,@dwContinueStatus
	
	ret

OnCreateThread endp
;退出进程
OnExitProcess proc hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	invoke crt_puts,offset g_szExitProcess;4
	mov eax,@dwContinueStatus
	
	ret

OnExitProcess endp
;退出线程
OnExitThread proc hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	invoke crt_puts,offset g_szExitThread;5
	mov eax,@dwContinueStatus
	
	ret

OnExitThread endp
;加载DLL
OnLoadDll proc uses esi hProcess:HANDLE, hThread:HANDLE, lpDebugEv:DWORD, lpContext:DWORD
	LOCAL @dwContinueStatus:dword
	LOCAL @lpDllName :LPVOID
	LOCAL @szBuff[260]:WORD
	LOCAL @szLen:UINT
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED
	
	;1 拿到debug_Event
	mov esi,lpDebugEv ;妈的这里是mov
	assume esi:ptr DEBUG_EVENT
	
	;2 读取dll的名字的地址
	invoke ReadProcessMemory,hProcess,[esi].u.LoadDll.lpImageName,addr @lpDllName,4,NULL
	
	;3 读取dll的名字
	invoke ReadProcessMemory,hProcess,@lpDllName,addr @szBuff,260*sizeof word,addr @szLen
	
	.if eax ==NULL
		mov eax,@dwContinueStatus
		ret
	.endif
	
	invoke crt__putws,addr @szBuff
	
	mov eax,@dwContinueStatus
	ret

OnLoadDll endp
;卸载DLL
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
	mov @dwContinueStatus,DBG_EXCEPTION_NOT_HANDLED;默认往上抛异常
	
	invoke RtlZeroMemory,addr @si,sizeof STARTUPINFO
	invoke RtlZeroMemory,addr @di,sizeof PROCESS_INFORMATION
	mov @si.cb , sizeof STARTUPINFO
	
	;1 创建扫雷进程
	invoke CreateProcess,offset g_szFileName,NULL,NULL,NULL,NULL,
								DEBUG_ONLY_THIS_PROCESS,NULL,NULL,addr @si,addr @di
	;2 等待调试事件
	.While 1
		invoke WaitForDebugEvent,addr @DebugEv,INFINITE
	
	;3 获得进程句柄
		invoke OpenProcess,PROCESS_ALL_ACCESS,NULL,@DebugEv.dwProcessId
	mov @hProcess,eax
	;4 获得线程句柄
		invoke OpenThread,THREAD_ALL_ACCESS,NULL,@DebugEv.dwThreadId
		mov @hThread,eax
	;5 得到线程上下文
		mov @Context.ContextFlags,CONTEXT_ALL
		invoke GetThreadContext,@hThread,addr @Context
	;6 进入循环判断上下文内容
		.if @DebugEv.dwDebugEventCode==EXCEPTION_DEBUG_EVENT;报告异常调试事件。
			invoke OnException,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
		.elseif @DebugEv.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT;报告创建进程调试事件。
			invoke OnCreateProcess,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
		
		.elseif @DebugEv.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT;报告创建线程调试事件
			invoke OnCreateThread,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
		.elseif @DebugEv.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT;报告退出进程调试事件	
			invoke OnExitProcess,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
		
		.elseif @DebugEv.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT;报告退出线程调试事件。	
			invoke OnExitThread,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
			
		.elseif @DebugEv.dwDebugEventCode==UNLOAD_DLL_DEBUG_EVENT;报告一个卸载DLL调试事件
			invoke OnUnLoadDll,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax	
			
		.elseif @DebugEv.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT;报告加载动态链接库（DLL）调试事件。
			invoke OnLoadDll,@hProcess,@hThread,addr @DebugEv,addr @Context
			mov @dwContinueStatus,eax
			
		.endif
	;7 恢复程上下文
		mov @Context.ContextFlags,CONTEXT_ALL
		invoke SetThreadContext,@hThread,addr @Context
	
	
	;8 关闭进程句柄和线程句柄	
		invoke CloseHandle,@hProcess
		invoke CloseHandle,@hThread
	
	;9 继续调试事件,意思就是调试程序的时候有事件来,你处理完了要继续.
		invoke ContinueDebugEvent,@DebugEv.dwProcessId,@DebugEv.dwThreadId,@dwContinueStatus
	.endw
	
	ret

Debug endp
START:
 invoke Debug




end START