#include <Windows.h>
#include <stdio.h>
#include "DllLogic.h"


HMODULE myHmod = 0;



DWORD Main(LPVOID param)
{
	/*FILE* temp = 0;
	AllocConsole();
	freopen_s(&temp, "CONIN$", "r", stdin);
	freopen_s(&temp, "CONOUT$", "w", stdout);
	freopen_s(&temp, "CONOUT$", "w", stderr);
	printf("nigger");*/


	Work();

	FreeLibraryAndExitThread(myHmod, 0);
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		myHmod = hModule;
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Main, nullptr, 0, nullptr);
		DisableThreadLibraryCalls(hModule);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}