#pragma once
#define UNICODE
#include <Windows.h>

#pragma pack(push, 1)

typedef struct _REQ_ECHO {
	BYTE WordCount;
	WORD EchoCount;
	WORD ByteCount;
	BYTE Buffer[1];
}REQ_ECHO, * PREQ_ECHO;

typedef struct _RESP_ECHO {
	BYTE WordCount;
	WORD SequenceNumber;
	WORD ByteCount;
	BYTE Buffer[1];
}RESP_ECHO, * PRESP_ECHO;

#pragma pack(pop)
