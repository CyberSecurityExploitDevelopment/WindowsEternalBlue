#pragma once
#include "smbmacros.h"

#pragma pack(push, 1)

typedef struct _REQ_TRANSACTION {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD MaxParameterCount;
	WORD MaxDataCount;
	BYTE MaxSetupCount;
	BYTE Reserved;
	WORD Flags;
	DWORD Timeout;
	WORD Reserved2;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD DataCount;
	WORD DataOffset;
	BYTE SetupCount;
	BYTE Reserved3;
	BYTE Buffer[1];
	//USHORT Setup[];                   //  Setup words (# = SetupWordCount)
	//USHORT ByteCount;                 //  Count of data bytes
	//UCHAR Name[];                     //  Name of transaction (NULL if Transact2)
	//UCHAR Pad[];                      //  Pad to SHORT or LONG
	//UCHAR Parameters[];               //  Parameter bytes (# = ParameterCount)
	//UCHAR Pad1[];                     //  Pad to SHORT or LONG
	//UCHAR Data[];                     //  Data bytes (# = DataCount)
}REQ_TRANSACTION, * PREQ_TRANSACTION;

typedef struct _REQ_NT_TRANSACTION {
	BYTE WordCount;
	BYTE MaxSetupCount;
	WORD Flags;
	DWORD TotalParameterCount;
	DWORD TotalDataCount;
	DWORD MaxParameterCount;
	DWORD MaxDataCount;
	DWORD ParameterCount;
	DWORD ParameterOffset;
	DWORD DataCount;
	DWORD DataOffset;
	BYTE SetupCount;
	WORD Function;
	WORD ByteCount;
	BYTE Buffer[1];
	//USHORT Setup[];                   // Setup words (# = SetupWordCount)
	//USHORT ByteCount;                 // Count of data bytes
	//UCHAR Pad1[];                     // Pad to LONG
	//UCHAR Parameters[];               // Parameter bytes (# = ParameterCount)
	//UCHAR Pad2[];                     // Pad to LONG
	//UCHAR Data[];                     // Data bytes (# = DataCount)
}REQ_NT_TRANSACTION, * PREQ_NT_TRANSACTION;

typedef struct _RESP_NT_TRANSACTION_INTERIM {
	BYTE WordCount;
	WORD ByteCount;
	BYTE Buffer[1];
}RESP_NT_TRANSACTION_INTERIM, * PRESP_NT_TRANSACTION_INTERIM;

typedef struct _RESP_NT_TRANSACTION {
	BYTE WordCount;		// Count of data bytes; value = 18 + SetupCount
	BYTE Reserved1;
	WORD Reserved2;
	DWORD TotalParameterCount;
	DWORD TotalDataCount;
	DWORD ParameterCount;
	DWORD ParameterOffset;
	DWORD ParameterDisplacement;
	DWORD DataCount;
	DWORD DataOffset;
	DWORD DataDisplacement;
	BYTE SetupCount;
	BYTE Buffer[1];
	//USHORT Setup[];                  // Setup words (# = SetupWordCount)
	//USHORT ByteCount;                // Count of data bytes
	//UCHAR Pad1[];                    // Pad to LONG
	//UCHAR Parameters[];              // Parameter bytes (# = ParameterCount)
	//UCHAR Pad2[];                    // Pad to SHORT or LONG
	//UCHAR Data[];                    // Data bytes (# = DataCount)
}RESP_NT_TRANSACTION, * PRESP_NT_TRANSACTION;

typedef struct _REQ_NT_TRANSACTION_SECONDARY {
	BYTE WordCount;
	BYTE Reserved1;
	WORD Reserved2;
	DWORD TotalParameterCount;
	DWORD TotalDataCount;
	DWORD ParameterCount;
	DWORD ParameterOffset;
	DWORD ParameterDisplacement;
	DWORD DataCount;
	DWORD DataOffset;
	DWORD DataDisplacement;
	BYTE Reserved3;
	WORD ByteCount;
	BYTE Buffer[1];
	//UCHAR Pad1[];                     // Pad to LONG
	//UCHAR Parameters[];               // Parameter bytes (# = ParameterCount)
	//UCHAR Pad2[];                     // Pad to LONG
	//UCHAR Data[];                     // Data bytes (# = DataCount)
}REQ_NT_TRANSACTION_SECONDARY, * PREQ_NT_TRANSACTION_SECONDARY;

/*typedef struct REQ_TRANSACTION2{
	BYTE WordCount;
	//words:
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD MaxParameterCount;
	WORD MaxDataCount;
	BYTE MaxSetupCount;
	BYTE Reserved1;
	WORD Flags;
	DWORD Timeout;
	WORD Reserved2;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD DataCount;
	WORD DataOffset;
	BYTE  SetupCount;
	BYTE  Reserved3;
	//USHORT Setup[SetupCount];
	//smb Data:
	BYTE Bytes[1];
}*PREQ_TRANSACTION2;
*/
typedef struct _RESP_TRANSACTION_INTERIM {
	BYTE WordCount;
	WORD ByteCount;
	BYTE Buffer[1];
}RESP_TRANSACTION_INTERIM, * PRESP_TRANSACTION_INTERIM;

typedef struct _RESP_TRANSACTION {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD Reserved;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD ParameterDisplacement;
	WORD DataCount;
	WORD DataOffset;
	WORD DataDisplacement;
	BYTE SetupCount;
	BYTE Reserved2;
	BYTE Buffer[1];
}RESP_TRANSACTION, * PRESP_TRANSACTION;

typedef struct _REQ_TRANSACTION_SECONDARY {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD ParameterDisplacement;
	WORD DataCount;
	WORD DataOffset;
	WORD DataDisplacement;
	WORD ByteCount;
	BYTE Buffer[1];
	//	UCHAR  Pad1[];
	//	UCHAR  Trans_Parameters[ParameterCount];
	//	UCHAR  Pad2[];
	//	UCHAR  Trans_Data[DataCount];
}REQ_TRANSACTION_SECONDARY, * PREQ_TRANSACTION_SECONDARY;

typedef struct _REQ_TRANSACTION2 {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD MaxParameterCount;
	WORD MaxDataCount;
	BYTE MaxSetupCount;
	BYTE Reserved1;
	WORD Flags;
	DWORD Timeout;
	WORD Reserved2;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD DataCount;
	WORD DataOffset;
	BYTE SetupCount;
	BYTE Reserved3;
	BYTE Buffer[1];
}REQ_TRANSACTION2, * PREQ_TRANSACTION2;


typedef struct _RESP_TRANSACTION2 {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD Reserved1;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD ParameterDisplacement;
	WORD DataCount;
	WORD DataDisplacement;
	BYTE SetupCount;
	BYTE Reserved2;
	BYTE Buffer[1];
}RESP_TRANSACTION2, * PRESP_TRANSACTION2;

typedef struct _REQ_TRANSACTION2_SECONDARY {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD ParameterDisplacement;
	WORD DataCount;
	WORD DataOffset;
	WORD DataDisplacement;
	WORD FID;
	WORD ByteCount;
	BYTE Buffer[1];
}REQ_TRANSACTION2_SECONDARY, * PREQ_TRANSACTION2_SECONDARY;


#pragma pack(pop)