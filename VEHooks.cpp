#include "VEHooks.h"
#include <stdio.h>


#define CALL_FIRST 1  
#define CALL_LAST 0


HANDLE VEHooks::ExceHandlr = 0;

void VEHooks::ReadyVEH(LONG(CALLBACK * VectoredHandler_)(_In_ PEXCEPTION_POINTERS)) {
	ExceHandlr = AddVectoredExceptionHandler(CALL_FIRST, VectoredHandler_);
	/*printf("AddVectoredExceptionHandler called (%p)\n", ExceHandlr);*/
}
void VEHooks::TerminateVEH() {
	/*printf("RemoveVectoredExceptionHandler called\n");*/
	RemoveVectoredExceptionHandler(ExceHandlr);
}

bool VEHooks::Hook(void* instruction, unsigned char* oldchar, DWORD* pageprotec) {
	DWORD PageProtect = 0;
	if (!VirtualProtect(instruction, 1, PAGE_EXECUTE_READWRITE, &PageProtect)) return false;

	*oldchar = *(unsigned char*)instruction;
	*(unsigned char*)instruction = 0xCC;
	if (pageprotec)*pageprotec = PageProtect;
	return oldchar;
}

bool VEHooks::Unhook(void* instruction, unsigned char oldchar, DWORD PageProtect) {
	DWORD temp = 0;
	*(unsigned char*)instruction = oldchar;
	if (VirtualProtect(instruction, 1, PageProtect, &temp))return true;
	else return false;
}
