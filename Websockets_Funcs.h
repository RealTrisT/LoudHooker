#pragma once
#include <stdlib.h>
#include <stdio.h>
extern "C" {
#include "EndianConversions.h"
}
#include "tSockets.h"
#include "Websockets_\sha1.hpp"

#define WEBSOCKETS_MAGICSTRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

//no null-terminators plz, websockets gets all fucky with those
bool Websockets_Send(tSocket::Connection* conect, char* buffer, unsigned __int64 bufferlen) {

	if (!conect->active) { printf("shit connect\n"); return false; }

	int SendResult = 0;
	unsigned char Overhead = 2;
	unsigned char payload = 0;

	if (bufferlen > 125) {
		if (bufferlen > 0xFFFF) { payload = 127; Overhead += 8; }		//bufflen only fits in 8bytes
		else { payload = 126; Overhead += 2; }		//bufflen fits in 2bytes
	}
	else						  payload = (unsigned char)bufferlen;	//bufflen fits in 7bits, no need for further overhead

	char* buffer_ = (char*)malloc(Overhead + bufferlen);				//allocate with overhead
	memcpy(buffer_ + Overhead, buffer, bufferlen);						//copy buffer into packet

	//*------------------------------------------------------*/printf("payload: %d, Overhead: %d\n", payload, Overhead);

	buffer_[0] = 0; buffer_[1] = 0;					//zero shit out so no accidents happen
	buffer_[0] = (char)0x81;						//FIN bit = 1, OPCODE = 1 (text)	
	buffer_[1] = (unsigned char)payload;			//set payload section
	buffer_[1] &= ~0x80;							//make sure that doesn't set the mask bit in case it's for some magic reason > 127					

	if (payload == 126)*(unsigned short*)&buffer_[2] = (unsigned short)ToLE16((short)bufferlen);	//if buffer > 125, set size in 'Extended Payload Length'
	else if (payload == 127)*(unsigned __int64*)&buffer_[2] = (unsigned __int64)ToLE64(bufferlen);  //if buffer > max unsigned short, set size in 'Extended Payload Length Continued'

	SendResult = send(conect->conn, buffer_, (int)bufferlen + Overhead, 0);	//send that boy (THERE'S A PROBLEM HERE, IF THE BUFFER IS TOO BIG IT SHOULD BE SEPARATED, THIS WILL JUST TRUNCATE THE SIZE TO INT)
	free(buffer_);															//free that boy
	if (SendResult == SOCKET_ERROR || SendResult == 0)return false;
	return true;
}

bool Websockets_Handshake(tSocket::Connection* client, char* firstPacket, unsigned int length) {
	char returnHash[29] = { 0 };
	//printf("shit1\n");
	char* occ = strstr(firstPacket, "Sec-WebSocket-Key: ");
	if (!occ)return false;
	occ += 19;

	//printf("shit2\n");
	char* lineend = strstr(occ, "\r\n");
	if (!lineend)return false;


	unsigned int SecWSAccept_l = (unsigned int)(lineend - occ);

	//printf("shit3\n");
	char* buffer_SecKey = (char*)malloc(SecWSAccept_l + 36 + 1);	//36 = magic key size //19 = size of secwebskey string //1 = nullterminator
	memcpy(buffer_SecKey, occ, SecWSAccept_l);						//basically size of key + magic string^
	memcpy(buffer_SecKey + SecWSAccept_l, WEBSOCKETS_MAGICSTRING, 36);
	buffer_SecKey[SecWSAccept_l + 36] = 0;
	//printf("shit4\n");
	sha1(buffer_SecKey).finalize().print_base64(returnHash);
	//printf("shit5: %s, %s\n", buffer_SecKey, returnHash);
	free(buffer_SecKey);

	//printf(WebsocketResponse);
	//printf("end of response---------------------------------\n");

	memcpy(WebsocketResponse + (129 - 4 - 28), returnHash, 28);

	//printf("dicks\n");
	//printf(WebsocketResponse);
	int workedsend = send(client->conn, WebsocketResponse, 129, 0);
	//printf("sent\n");
	if (workedsend == SOCKET_ERROR || workedsend == 0)return false;
	return true;
}