#include <windows.h>
typedef  int(__stdcall *MessageBox_type)(
	HWND hWnd,  // handle of owner window
	LPCTSTR lpText,  // address of text in message box
	LPCTSTR lpCaption, // address of title of message box
	UINT uType  // style of message box
	);
MessageBox_type old_MessageBoxA;
#pragma pack(1) 

typedef struct _JMPCODE
{
	BYTE jmp;
	DWORD addr;
}JMPCODE, *PJMPCODE;
_declspec(naked)
VOID __stdcall my_MessageBox(
HWND hWnd,  // handle of owner window
LPCTSTR lpText,  // address of text in message box
LPCTSTR lpCaption, // address of title of message box
UINT uType  // style of message box
)
{
	__asm
	{
		PUSH EBP
			MOV EBP, ESP
	}
	printf("Hook and get parameter %x,%s,%s,%x\n", hWnd, lpText, lpCaption,
		uType);
	__asm
	{
		mov ebx, old_MessageBoxA
			add ebx, 5
			jmp ebx
	}
	printf("Hook Error\n");
}
VOID InLine_Hook_MessageBoxA()
{
	JMPCODE jcode;
	HMODULE h = LoadLibraryA("user32.dll");
	old_MessageBoxA = (MessageBox_type)(GetProcAddress(h, "MessageBoxA"));
	jcode.jmp = 0xe9;
	jcode.addr = (DWORD)(&my_MessageBox) - (DWORD)(&MessageBoxA) - 5;
	old_MessageBoxA = &MessageBoxA;
	WriteProcessMemory(GetCurrentProcess(), &MessageBoxA, &jcode, sizeof(JMPCODE),
		NULL);
	CloseHandle(h);
}
int main(int argc, char* argv[])
{
	InLine_Hook_MessageBoxA();
	MessageBoxA(NULL, "123", "321", MB_OK);
	return 0;
}