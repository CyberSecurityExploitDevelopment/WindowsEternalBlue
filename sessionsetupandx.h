#pragma once
#include "smbtransaction.h"

#pragma pack(push, 1)

typedef struct ANDX {
	BYTE AndxCommand;
	BYTE Reserved;
	WORD AndxOffset;
}*PANDX;


typedef struct _REQ_SESSIONSETUP_ANDX {
	BYTE WordCount;
	ANDX andx;
	WORD MaxBufferSize;
	WORD MaxMpxCount;
	WORD VcNumber;
	DWORD SessionKey;
	WORD PasswordLength;
	DWORD Reserved;
	WORD ByteCount;
	union {
		struct {
			BYTE Password;
			BYTE Buffer[1];
		};
		BYTE Bytes[2];
	};
}REQ_SESSIONSETUP_ANDX, * PREQ_SESSIONSETUP_ANDX;

typedef struct _REQ_NT_SESSIONSETUP_ANDX {
	BYTE WordCount;
	ANDX Andx;
	WORD MaxBufferSize;
	WORD MaxMpxCount;
	WORD VcNumber;
	DWORD SessionKey;
	WORD CaseInsensitivePasswordLength;
	WORD CaseSensitivePasswordLength;
	DWORD Reserved;
	DWORD Capabilities;
	WORD ByteCount;
	BYTE Buffer[1];
}REQ_NT_SESSIONSETUP_ANDX, * PREQ_NT_SESSIONSETUP_ANDX;

typedef struct _RESP_SESSIONSETUP_ANDX {
	BYTE WordCount;
	ANDX Andx;
	WORD Action;
	WORD ByteCount;
	BYTE Buffer[1];
}RESP_SESSIONSETUP_ANDX, * PRESP_SESSIONSETUP_ANDX;


typedef struct _REQ_WRITE_ANDX {
	BYTE WordCount;
	union {
		ANDX andx;
		struct {
			BYTE AndxCommand;
			BYTE AndxReserved;
			WORD AndxOffset;
		};
	};
	WORD Fid;
	DWORD Offset;
	DWORD Timeout;
	WORD WriteMode;
	WORD Remaining;
	WORD Reserved;
	WORD DataLength;
	WORD DataOffset;
	WORD ByteCount;
	BYTE Buffer[1];
}REQ_WRITE_ANDX, * PREQ_WRITE_ANDX;

typedef struct _RESP_WRITE_ANDX {
	BYTE WordCount;
	//Words
	ANDX Andx;
	WORD Count;
	WORD Available;
	DWORD Reserved;
	//SMB_DATA
	WORD ByteCount;
}RESP_WRITE_ANDX, * PRESP_WRITE_ANDX;

#pragma pack(pop)