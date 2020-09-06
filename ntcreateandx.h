#pragma once
#include "sessionsetupandx.h"

#pragma pack(push, 1)

typedef struct REQ_NT_CREATE_ANDX
{
	BYTE WordCount;
	BYTE AndxCommand;
	BYTE AndxReserved;
	WORD AndxOffset;
	BYTE Reserved;
	WORD NameLength;
	DWORD Flags;
	DWORD RootDirectoryFID;
	DWORD DesiredAccess;
	LARGE_INTEGER AllocationSize;
	DWORD ExtFileAttributes;
	DWORD ShareAccess;
	DWORD CreateDisposition;
	DWORD CreateOptions;
	DWORD ImpersonationLevel;
	BYTE SecurityFlags;
	WORD ByteCount;
	BYTE Bytes[1];
}*PREQ_NT_CREATE_ANDX;


typedef struct RESP_NT_CREATE_ANDX {
	BYTE AndxCommand;
	BYTE AndxReserved;
	WORD AndxOffset;
	BYTE OpLockLevel;
	WORD Fid;
	BYTE etc[1];
}*PRESP_NT_CREATE_ANDX;


#pragma pack(pop)