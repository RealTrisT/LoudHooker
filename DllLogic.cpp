#include "DllLogic.h"
#include "WebResources.h"

#include "tSockets.h"
#include "VEHooks.h"
#include "Websockets_Funcs.h"

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <Shlwapi.h>

extern "C" {
#include "WebFuncs.h"
#include "EndianConversions.h"
}



bool Running = true;

struct CChook {
	void* funcptr = 0;
	unsigned char oldchar = 0;
	char* formatting = 0;
}hook_arry[10], *laster;


tSocket* SockPtr	  = 0;
tSocket::Connection* Websockets_Connection = 0;
bool Websockets_Connection_Active = false;

HANDLE AcceptThread_h = 0;
HANDLE WebsocketsRecvThread_h = 0;
DWORD WINAPI WebsocketsRecvThread(_In_ LPVOID lpParameter);

void EscapeJson(std::string* strang) {
	size_t strlen = (*strang).length();
	bool foundone = true;
	while (foundone) {
		foundone = false;
		strlen = (*strang).length();
		for (size_t i = 0; i < strlen; i++) {
			if ((*strang)[i] == '"' || (*strang)[i] == '/' || (*strang)[i] == '\\') {
				if ((*strang)[i] == '\\' && ((*strang)[i + 1] == '\\' || (*strang)[i + 1] == '/' || (*strang)[i + 1] == '"')) { i++; continue; }
				if ((i && (*strang)[i - 1] != '\\') || !i){	
					(*strang).insert(i, "\\");
					foundone = true;
					//printf("found\n"); 
					break;
		}	}	}
	}
}


//f = float
//d = double
//return -> how much the format pointer has to go forward

char XMM_Format(char* buffer, int buffersize, char formatChar, char WhichXmm, PEXCEPTION_POINTERS exc) {
	//printf("formatting for XMM%d\n", WhichXmm);

	M128A reg = { 0,0 };
	if		(WhichXmm == 0)reg = exc->ContextRecord->Xmm0;
	else if (WhichXmm == 1)reg = exc->ContextRecord->Xmm1;
	else if (WhichXmm == 2)reg = exc->ContextRecord->Xmm2;
	else if (WhichXmm == 3)reg = exc->ContextRecord->Xmm3;
	else if (WhichXmm == 4)reg = exc->ContextRecord->Xmm4;
	else if (WhichXmm == 5)reg = exc->ContextRecord->Xmm5;
	else if (WhichXmm == 6)reg = exc->ContextRecord->Xmm6;
	else if (WhichXmm == 7)reg = exc->ContextRecord->Xmm7;
	else if (WhichXmm == 8)reg = exc->ContextRecord->Xmm8;
	else if (WhichXmm == 9)reg = exc->ContextRecord->Xmm9;
	else if (WhichXmm == 10)reg = exc->ContextRecord->Xmm10;
	else if (WhichXmm == 11)reg = exc->ContextRecord->Xmm11;
	else if (WhichXmm == 12)reg = exc->ContextRecord->Xmm12;
	else if (WhichXmm == 13)reg = exc->ContextRecord->Xmm13;
	else if (WhichXmm == 14)reg = exc->ContextRecord->Xmm14;
	else if (WhichXmm == 15)reg = exc->ContextRecord->Xmm15;
	else{ buffer[0] = 0;  printf("faile\n");  return 1; }

	if (formatChar == 'f') {
		snprintf(buffer, buffersize, "[\"%f\", \"%f\", \"%f\", \"%f\"]", *(float*)(((char*)&(reg.High)) + 4), *(float*)(((char*)&(reg.High)) + 0), *(float*)(((char*)&(reg.Low)) + 4), *(float*)(((char*)&(reg.Low)) + 0));
		return 1;
	}else if (formatChar == 'd') {
		snprintf(buffer, buffersize, "[\"%f\", \"%f\"]", reg.High, reg.Low);
		return 1;
	}
	return 1;
}

char R_Format(char* buffer, int buffersize, char* formatting, PEXCEPTION_POINTERS exc) {
	char formatform[3] = { '%', '_', 0};
	DWORD64 register_ = 0;
	char offset = 0;

	offset += 2;
	if (formatting[0] == 'C') {							//RCX
		register_ = exc->ContextRecord->Rcx;
	} else if (formatting[0] == 'D') {					//RDX/RDI
		if (formatting[1] == 'X') register_ = exc->ContextRecord->Rdx;
		else register_ = exc->ContextRecord->Rdi;
	} else if (formatting[0] <= 0x39 && formatting[0] >= 0x30) { //r8-15
		if (formatting[1] <= 0x39 && formatting[1] >= 0x30) {				//r10 - r15
			char R_ = (formatting[0] - 0x30) * 10 + (formatting[1] - 0x30);
			switch (R_) {
			case 10: register_ = exc->ContextRecord->R10;
			case 11: register_ = exc->ContextRecord->R11;
			case 12: register_ = exc->ContextRecord->R12;
			case 13: register_ = exc->ContextRecord->R13;
			case 14: register_ = exc->ContextRecord->R14;
			case 15: register_ = exc->ContextRecord->R15;
			default: {buffer[0] = 0; return offset; break; }}	//if it has 2 digits but it's not 10 <= x <= 15 (bad register)
		} else {															//r8 / r9
			offset--;											//unlike the other R registers this one's name is only 2 chars long
			if (formatting[0] == '8')register_ = exc->ContextRecord->R8;
			else if (formatting[0] == '9')register_ = exc->ContextRecord->R9;
			else{ buffer[0] = 0; return offset; }				//if it has 1 digit but it's not 8 or 9 (bad register)
		}
	} else if (formatting[0] == 'A') {					//RAX
		register_ = exc->ContextRecord->Rax;
	} else if (formatting[0] == 'S') {					//RSP/RSI
		if (formatting[1] == 'P') register_ = exc->ContextRecord->Rsp;
		else register_ = exc->ContextRecord->Rsi;
	} else if (formatting[0] == 'B') {					//RBX/RBP
		if (formatting[1] == 'P') register_ = exc->ContextRecord->Rbp;
		else register_ = exc->ContextRecord->Rbx;
	}else{ buffer[0] = 0;  return offset; }

	formatform[1] = formatting[offset];
	snprintf(buffer, buffersize, formatform, register_);
	offset++;

	return offset;
}

void Stack_Format(char* buffer, int buffersize, char formatChar, unsigned __int64 stack_begin_distance, char* stackptr) {
	char formatform[3] = { '%', '_', 0 };
	formatform[1] = formatChar;
	if (formatChar == 'F') {
		snprintf(buffer, buffersize, formatform, *(float*)(stackptr + stack_begin_distance));
	}
	else {
		snprintf(buffer, buffersize, formatform, *(__int64*)(stackptr + stack_begin_distance));
	}
	return;
}

std::string Format_Out(CChook* hk, PEXCEPTION_POINTERS exc) {
	std::string yasse = "";
	char* formatting = hk->formatting;
	char buffer[1000] = { 0 };
	char XMM_Index = 0;

	snprintf(buffer, 1000, "0x%p", (void*)exc->ContextRecord->Rip);
	yasse.append("[\"").append(buffer).append("\"");
	for (int f = 0;*formatting;f++) {
		if (*formatting == ' ') { formatting++; continue; }

		if (*formatting == 'X') { //if it's an XMM variable
			yasse.append(", ");

			//-------------------------------------------------------------------------------------------------------------------------------------XMM
			formatting += 3;	  //"XMM"
			char WhichXmm = formatting[0] - 0x30;					//some ascii table action: get the xmm index (or at least the first digit)
			formatting++;		//first and possibly last xmm digit
			if (formatting[0] <= 0x35) {							//if it's a 2digit XMM (10-15)
				WhichXmm = WhichXmm * 10 + (formatting[4] - 0x30);	//now we have the xmm index for sure, and we know that the 
				formatting++;	//second digit of the xmm
			}
			formatting += XMM_Format(buffer, 1000, formatting[0], WhichXmm, exc);
			//-------------------------------------------------------------------------------------------------------------------------------------

			yasse.append(buffer);
		} else if (*formatting == 'R') {
			yasse.append(", \"");


			//-------------------------------------------------------------------------------------------------------------------------------------REGISTER
			formatting++;		//"R"
			formatting += R_Format(buffer, 1000, formatting, exc);
			//-------------------------------------------------------------------------------------------------------------------------------------

			std::string temp = buffer;
			EscapeJson(&temp);
			yasse.append(temp).append("\"");
		} else if (*formatting == 'S') {
			yasse.append(", \"");

			//-------------------------------------------------------------------------------------------------------------------------------------STACK
			formatting++;
			int i = 0;
			unsigned __int64 stack_more = 0;
			for (; formatting[i] <= 0x39 && formatting[i] >= 0x30; i++)stack_more = stack_more * 10 + (formatting[i] - 0x30);
			formatting += i;
			Stack_Format(buffer, 1000, formatting[0], stack_more, (char*)exc->ContextRecord->Rsp);
			formatting++;
			//-------------------------------------------------------------------------------------------------------------------------------------

			std::string temp = buffer;
			EscapeJson(&temp);
			yasse.append(temp).append("\"");
		}
	}
	yasse.append("]");
	//printf("Sending json: %s\n", yasse.c_str());
	return yasse;
}

void ProcessInMessage(char* buffer, __int64 length) {
	if (*buffer == 'a') {
		for (char i = 0; i < 10; i++){
			if (!hook_arry[i].funcptr) {
				char* buffText = 0;	int indux = 0;							//formatting pointer, indux is gonna be an index variable used to find the "formatting pointer"
				void* funcptr = 0;											//function pointer
				char* buffr = (char*)malloc(500); buffr[299] = 0;			//format buffer (get at least a null terminator inthere)
				sscanf_s(buffer + 1, "%p", &funcptr);						//make the text pointer into 8byte actual pointer
				for (buffText = buffer, indux = 0; indux < length && *buffText != ' ' && *buffText != 0; buffText++, indux++); indux++;	//get the formatting pointer
				if (indux == length || !*buffText) { free(buffr); printf("fail lmao"); return; }										//no formatting info
				memcpy(buffr, buffText + 1, length - indux); buffr[length - indux] = 0;													//copy it into the buffer and null-terminate it in case
				for (char j = 0; j < 10; j++)if (hook_arry[j].funcptr == funcptr)return;	//already had one of these														 the sender doesn't
				if (VEHooks::Hook(funcptr, &(hook_arry[i].oldchar))) {						//actually hook shit
					hook_arry[i].funcptr = funcptr;	hook_arry[i].formatting = buffr;		//make this object point to something and formatting have its shit
					/*printf("hooked %p, formatting: %s\n", funcptr, buffr);*/					
				}
				else printf("failed to hook\n");
				break;
			}
		}
	} else if(*buffer == 'r'){
		void* funcptr = 0;
		sscanf_s(buffer + 1, "%p", &funcptr);
		for (char i = 0; i < 10; i++) {
			if (hook_arry[i].funcptr == funcptr) {
				if (VEHooks::Unhook(funcptr, hook_arry[i].oldchar))/*printf("unhooked %p\n", funcptr)*/;
				hook_arry[i].funcptr = 0; hook_arry[i].oldchar = 0;  free(hook_arry[i].formatting); hook_arry[i].formatting = 0;
				break;
			}
		}
	} else if (*buffer == 'q') {
		Running = false;
	}
	return;
}
void BreakpointHit(CChook* hk, PEXCEPTION_POINTERS exc) {
	std::string lebuff = Format_Out(hk, exc);
	//char buffer[1000] = { 0 };
	//sprintf_s(buffer, "Triggered. RCX: %p, RDX: %p, R8: %p, R9: %p", (void*)exc->ContextRecord->Rcx, (void*)exc->ContextRecord->Rdx, (void*)exc->ContextRecord->R8, (void*)exc->ContextRecord->R9);
	if (Websockets_Connection_Active)Websockets_Send(Websockets_Connection, (char*)lebuff.c_str(), lebuff.length());
	//printf("hit\n");
}

LONG CALLBACK VectoredHandler_(_In_ PEXCEPTION_POINTERS exc) {
	if (exc->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		CChook* chosenhook = 0;
		for (char i = 0; i < 10; i++)	if (hook_arry[i].funcptr == (void*)exc->ContextRecord->Rip) { chosenhook = &hook_arry[i]; break; }
		if (!chosenhook) { printf("nugg\n"); return EXCEPTION_CONTINUE_SEARCH; }

		*(unsigned char*)chosenhook->funcptr = chosenhook->oldchar;
		laster = chosenhook;
		exc->ContextRecord->EFlags |= 0x100;

		BreakpointHit(chosenhook, exc);
	}
	else if (exc->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		*(unsigned char*)(laster->funcptr) = 0xCC;
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

bool ConnectedClient(tSocket::Connection* client) {
	//printf("connection came in\n");
	char buffer[4096] = { 0 };
	int bytesread = 0;

	int timeout = 500;
	if (setsockopt(client->conn, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int)) == SOCKET_ERROR) {printf("setsockopt failed (set .5s)\n");return false;}
									//chrome for some reason seems to some times block websockets connections for a stupid ammount of time when first connecting, 
									//so close that shit until it fucking decides to send the packet at once

	/*printf("receiving\n");*/
	bytesread = recv(client->conn, buffer, 4096, 0);
	/*printf("received\n");*/
	if (bytesread == SOCKET_ERROR || bytesread == 0) { /*printf("failed to receive: %d\n", WSAGetLastError());*/ return false; }

	if (strstr(buffer, ".jpg")) {
		send(client->conn, hackpage, full_page_size - 1, 0);
		/*printf("sent page\n");*/
	}
	else if (strstr(buffer, ".png")) {
		//printf("handshaking\n");
		if (Websockets_Handshake(client, buffer, bytesread)) { Websockets_Connection = client; Websockets_Connection_Active = true;	printf("HandShook\n");}
		else return false;

		timeout = 0;
		if (setsockopt(client->conn, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int)) == SOCKET_ERROR) {/*printf("setsockopt failed (set inf)\n");*/return false;} 
									//reset the timeout so we can recieve socket stuff

		if (!(WebsocketsRecvThread_h = CreateThread(0, 0, WebsocketsRecvThread, client, 0, 0)))return false;
		return true;
	}
	return false;
}

DWORD WINAPI AcceptThread(_In_ LPVOID lpParameter) {
	((tSocket*)lpParameter)->WaitForConnections();
	return 0;
}

DWORD WINAPI WebsocketsRecvThread(_In_ LPVOID lpParameter) {
	char buffer[4096] = { 0 };
	char* actualMessage = 0;
	unsigned __int64 actualMessageLength = 0;
	int result = recv(((tSocket::Connection*)lpParameter)->conn, buffer, 4096, 0);
	while (result != SOCKET_ERROR && result != 0) {
		WsDecodeMessage((WsFrame*)buffer, result, &actualMessage, &actualMessageLength);
		//work
		//printf("recv %s\n", actualMessage);
		ProcessInMessage(actualMessage, actualMessageLength);
		//work
		result = recv(((tSocket::Connection*)lpParameter)->conn, buffer, 4096, 0);
	}
	SockPtr->CloseConnection(((tSocket::Connection*)lpParameter));
	Websockets_Connection_Active = false;
	/*printf("Websock Connection Closed\n");*/
	return 0;
}

void Work() {
	tSocket socket("8081", 2);	SockPtr = &socket;
	if (!socket.Startup()) { printf("Socket Failed To Startup\n"); return; }
	socket.ClientConnected = ConnectedClient;
	if (!(AcceptThread_h = CreateThread(0, 0, AcceptThread, &socket, 0, 0))) { socket.Shutdown();  return; }

	VEHooks::ReadyVEH(VectoredHandler_);
	system("start http://localhost:8081/.jpg");
	while (/*!GetAsyncKeyState(VK_F1) && */Running)Sleep(30); 
	/*while (PathFileExists("C:\\Users\\TrisT\\Desktop\\fuiles\\hacks\\Mine\\Learning Projects\\LoudHooker\\a.txt")) { Sleep(1000); }
	CloseHandle(CreateFile("C:\\Users\\TrisT\\Desktop\\fuiles\\hacks\\Mine\\Learning Projects\\LoudHooker\\a.txt", GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL));
	*/


	for (char i = 0; i < 10; i++)if (hook_arry[i].funcptr) { VEHooks::Unhook(hook_arry[i].funcptr, hook_arry[i].oldchar); free(hook_arry[i].formatting); }


	VEHooks::TerminateVEH();
	socket.Shutdown();

	if(AcceptThread_h)
		if (WaitForSingleObject(AcceptThread_h		  , 500) == WAIT_TIMEOUT)TerminateThread(AcceptThread_h			, 0);
	if (WebsocketsRecvThread_h && Websockets_Connection_Active)
		if (WaitForSingleObject(WebsocketsRecvThread_h, 500) == WAIT_TIMEOUT)TerminateThread(WebsocketsRecvThread_h	, 0);
	//printf("ended\n");
	return;
}