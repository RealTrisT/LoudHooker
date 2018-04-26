#pragma once

#include <Windows.h>
extern "C" {
#include "lend/ld32.h"
}
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>

#define DR0_DR7_L 0x01
#define DR1_DR7_L 0x04
#define DR2_DR7_L 0x10
#define DR3_DR7_L 0x40

#define DR0_DR7_G 0x02
#define DR1_DR7_G 0x08
#define DR2_DR7_G 0x20
#define DR3_DR7_G 0x80

#define DR0_DR7_LG 0x03
#define DR1_DR7_LG 0x0C
#define DR2_DR7_LG 0x30
#define DR3_DR7_LG 0xC0

#define DR_RES		0x400
#define DR_RES_LEGE 0x700

class DR0_HOOK {
	static const int maxThreadIDs = 500;
	DWORD	threadIDs[maxThreadIDs] = { 0 };
	bool ishooked = false;

public:
	bool UpdateProcessThreads() {
		DWORD pID = GetCurrentProcessId();
		memset(threadIDs, 0, maxThreadIDs * sizeof(DWORD));

		int lastThreadID = 0;
		HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
		THREADENTRY32 te32;

		hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE)
			return(FALSE);
		te32.dwSize = sizeof(THREADENTRY32);

		if (!Thread32First(hThreadSnap, &te32))
		{
			CloseHandle(hThreadSnap);
			return(FALSE);
		}
		do
		{
			if (te32.th32OwnerProcessID == pID)
			{
				threadIDs[lastThreadID++] = te32.th32ThreadID;
			}
		} while (lastThreadID < maxThreadIDs && Thread32Next(hThreadSnap, &te32));
		if (lastThreadID == 500)printf("Max Amount Of Threads Reached\n");
		CloseHandle(hThreadSnap);
		return(TRUE);
	}
	void SetDebugRegisters(char DR, void* Addr) {
		HANDLE thready = 0;
		CONTEXT yee = { 0 };
		for (int i = 0; threadIDs[i]; i++) {
			if (threadIDs[i] != GetCurrentThreadId() && (thready = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, 0, threadIDs[i]))) {

				yee = { 0 };
				yee.ContextFlags = CONTEXT_DEBUG_REGISTERS;

				if (!GetThreadContext(thready, &yee))printf("BigFax: %d\n", GetLastError());

				printf("FirstContext: %p - %p\n", (void*)yee.Dr0, (void*)yee.Dr7);

				if (DR == 0)		{yee.Dr0 = (DWORD64)Addr; if (Addr)yee.Dr7 |= DR0_DR7_LG; else yee.Dr7 &= ~DR0_DR7_LG;}
				else if (DR == 1)	{yee.Dr1 = (DWORD64)Addr; if (Addr)yee.Dr7 |= DR1_DR7_LG; else yee.Dr7 &= ~DR1_DR7_LG;}
				else if (DR == 2)	{yee.Dr2 = (DWORD64)Addr; if (Addr)yee.Dr7 |= DR2_DR7_LG; else yee.Dr7 &= ~DR2_DR7_LG;}
				else if (DR == 3)	{yee.Dr3 = (DWORD64)Addr; if (Addr)yee.Dr7 |= DR3_DR7_LG; else yee.Dr7 &= ~DR3_DR7_LG;}

				if (yee.Dr0 || yee.Dr1 || yee.Dr2 || yee.Dr3)	yee.Dr7 |=  DR_RES_LEGE;
				else											yee.Dr7 &= ~DR_RES_LEGE;

				printf("SirstContext: %p - %p\n", (void*)yee.Dr0, (void*)yee.Dr7);

				if (SetThreadContext(thready, &yee))printf("DebugRegister (Dr%d) Updated\n", DR);
				else printf("big fucktruk\n");

				CloseHandle(thready);
			}
		}
	}
	
	bool Hook(void* what) {
		SetDebugRegisters(0, what);
		ishooked = true;
		return true;
	}

	bool Unhook() {
		SetDebugRegisters(0, 0);
		ishooked = false;
		return true;
	}
};