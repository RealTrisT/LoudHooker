#pragma once
#include <Windows.h>


class VEHooks {
	static HANDLE ExceHandlr;
public:
	static void ReadyVEH(LONG(CALLBACK * VectoredHandler_)(_In_ PEXCEPTION_POINTERS));
	static void TerminateVEH();
	static bool Hook(void* instruction, unsigned char* oldchar, DWORD* pageprotec = 0);
	static bool Unhook(void* instruction, unsigned char oldchar, DWORD PageProtect = PAGE_EXECUTE_READWRITE);
};