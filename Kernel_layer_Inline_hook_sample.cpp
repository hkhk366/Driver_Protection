#pragma once
#ifdef __cplusplus
extern "C"
{
#endif
#include <NTDDK.h>
#ifdef __cplusplus
}
#endif
bool ssdthook_flag = false;
ULONG  RealNtOpenAddress;
HANDLE  MyPID;
extern "C"  typedef NTSTATUS  __stdcall NTOPENPROCESS
(
OUT PHANDLE ProcessHandle,
IN ACCESS_MASK AccessMask,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN PCLIENT_ID ClientId
);
NTOPENPROCESS  * RealNtOpenProcess;
PEPROCESS EP;
#pragma PAGECODE
extern "C" NTSTATUS __declspec(naked) __stdcall MyNtOpenProcess(
	OUT  PHANDLE ProcessHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes,
	IN  PCLIENT_ID ClientId)
{
	NTSTATUS  rc;
	HANDLE  PID;
	if ((ClientId != NULL))
	{
		PID = ClientId->UniqueProcess;
		KdPrint(("------------------------- PID=%d--------------\n", (int*)PID));
		if (PID == MyPID)
		{
			KdPrint(("Protected PID=%d \n", (int)MyPID));
			ProcessHandle = NULL;
			rc = STATUS_ACCESS_DENIED;
			EP = PsGetCurrentProcess();
			KdPrint((" ACESS Process Name --:%s--\n", (PTSTR)((ULONG)EP + 0x174)));
			__asm
			{
				retn 0x10
			}
		}
	}
	__asm
	{  int 3
		push  0C4h
		mov eax, RealNtOpenProcess
		add eax, 5
		jmp eax
	}
}
#pragma PAGECODE
VOID Hook()
{
	ssdthook_flag = true;
	LONG *SSDT_Adr, SSDT_NtOpenProcess_Cur_Addr, t_addr;
	KdPrint(("Load driver.\n"));
	t_addr = (LONG)KeServiceDescriptorTable->ServiceTableBase;
	SSDT_Adr = (PLONG)(t_addr + 0x7A * 4);
	SSDT_NtOpenProcess_Cur_Addr = *SSDT_Adr;
	RealNtOpenAddress = *SSDT_Adr;
	RealNtOpenProcess = (NTOPENPROCESS *)RealNtOpenAddress;
	KdPrint(("Real NtOpenProcess address: %x\n", (int)RealNtOpenAddress));
	KdPrint(("My NTOpenProcess address: %x\n", (int)MyNtOpenProcess));
	__asm
	{
		cli
			mov eax, cr0
			and eax, not 10000h //and eax,0FFFEFFFFh
			mov cr0, eax
	}
	ULONG jmpaddr = (ULONG)MyNtOpenProcess - RealNtOpenAddress - 5;
	SSDT_Adr = (PLONG)*SSDT_Adr;
	__asm
	{
		mov ebx, SSDT_Adr
			mov byte ptr ds : [ebx], 0xe9
			mov eax, jmpaddr
			mov DWORD ptr ds : [ebx + 1], eax
	}
	__asm
	{ int 3
		mov  eax, cr0
		or  eax, 10000h
		mov  cr0, eax
		sti
	}
	return;
}
#pragma PAGECODE
VOID UnHook()
{
	ULONG Old_ssdt;
	Old_ssdt = (ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x7A * 4;
	if (ssdthook_flag)
	{
		ssdthook_flag = false;
		__asm
		{
			cli
				mov  eax, cr0
				and  eax, not 10000h
				mov  cr0, eax
		}
		*((ULONG*)Old_ssdt) = (ULONG)RealNtOpenAddress;
		__asm
		{
			mov  eax, cr0
				or  eax, 10000h
				mov  cr0, eax
				sti
		}
		KdPrint(("UnHook recover SSDT\n"));
	}
	return;
}