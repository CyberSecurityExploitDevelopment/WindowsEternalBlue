#pragma once
#include "sessionsetupandx.h"

#pragma pack(push, 1)

typedef struct _REQ_TREE_CONNECT_ANDX {
	BYTE WordCount;
	ANDX Andx;
	WORD Flags;
	WORD PasswordLength;
	WORD Bytecount;
	union {
		struct {
			BYTE Password;
			BYTE Buffer[1];
		};
		BYTE Bytes[2];
	};
}REQ_TREE_CONNECT_ANDX, *PREQ_TREE_CONNECT_ANDX;

typedef struct _RESP_TREE_CONNECT_ANDX {
	BYTE WordCount;
	ANDX Andx;
	WORD OptionalSupport;
	WORD ByteCount;
	BYTE Buffer[1];
}RESP_TREE_CONNECT_ANDX, * PRESP_TREE_CONNECT_ANDX;


#pragma pack(pop)