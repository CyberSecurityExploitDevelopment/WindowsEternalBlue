#pragma once
#include "windowssocket.h"
#define SMB_MACROS
/*
 *
 *	Smb.Flags Mask defines:
 *
 */

#define SMB_FLAGS_LOCK_AND_READ_OK 0x01
#define SMB_FLAGS_BUF_AVAIL 0x2
#define SMB_FLAGS_CASE_INSENSITIVE 0x08
#define SMB_FLAGS_CANONICALIZED_PATHS 0x10
#define SMB_FLAGS_OPLOCK 0x20
#define SMB_FLAGS_REPLY 0x80

 /*
  *
  *
  *	Smb Macros
  *
  *
  */

#define GetSocket(sockptr)		\
*(SOCKET *)(sockptr)
#define PutSocket(dest, value)	\
*(SOCKET *)(dest) = (value)

#define GetUshort(src)			\
*(WORD *)(src)
#define PutUshort(dst, val)		\
*(WORD *)(dst) = (val)

#define GetUlong(src)			\
*(DWORD *)(src)
#define PutUlong(dst, val)		\
*(DWORD *)(dst) = (val)

#define GetUlongPtr(src)		\
*(DWORD_PTR*)(src)
#define PutUlongPtr(dst, val)	\
*(DWORD_PTR *)(dst) = (val)

#define GetUlonglong(src)		\
*(ULONGLONG*)(src)
#define PutUlonglong(dest, value)	\
*(ULONGLONG *)(dest) = (value)

#define GetUnsigned(src)		\
*(unsigned *)(src)
#define PutUnsigned(dst, val)	\
*(unsigned *)(dst) = (val)


#define byteswap16(value)		\
((WORD)((((value) >> 8) & 0xFF) | (((value) & 0xFF) << 8)))
#define byteswap32(value)		\
((((value) & 0xFF000000) >> 24) | (((value) & 0x00FF0000) >> 8) | (((value) & 0xFF00) << 8) | (((value) & 0xFF) << 24))
#define byteswap64(value)		\
((((value) & 0xFF00000000000000ULL) >> 56)		\
|	(((value) & 0x00FF000000000000ULL) >> 40)	\
|	(((value) & 0x0000FF0000000000ULL) >> 24)	\
|	(((value) & 0x000000FF00000000ULL) >> 8)	\
|	(((value) & 0x00000000FF000000ULL) << 8)	\
|	(((value) & 0x0000000000FF0000ULL) << 24)	\
|	(((value) & 0x000000000000FF00ULL) << 40)	\
|	(((value) & 0x00000000000000FFULL) << 56))

#define badsock(sfd)	\
((BOOLEAN)((sfd) == INVALID_SOCKET) ? TRUE : FALSE)
#define validsock(sfd)	\
((BOOLEAN)((sfd) != INVALID_SOCKET) ? TRUE : FALSE)

#define isnull(x)		\
((BOOLEAN)((x) == NULL) ? TRUE : FALSE)
#define notnull(x)		\
((BOOLEAN)((x) != NULL) ? TRUE : FALSE)

#define issockerr(status)	\
((BOOLEAN)((status) == SOCKET_ERROR) ? TRUE : FALSE)

#define MAKEUNSIGNED(x)		\
((unsigned)(x))
#define MAKEPBYTE(x)		\
((PBYTE)(x))
#define MAKEPSMB(x)			\
((PSMB_HEADER)(x))
#define MAKEPWSTR(x)		\
((PWSTR)(x))
#define MAKEPCWSTR(x)		\
((PCWSTR)(x))
#define MAKEPWORD(x)		\
((WORD *)(x))
#define MAKEPDWORD(x)		\
((DWORD *)(x))
#define MAKEPVOID(x)		\
((PVOID)(x))


#define errmsg(func, line, err)		\
(fwprintf_s(stderr, __LPREFIX("[-] function %S failed on line %u with error 0x%08X\n"), func, MAKEUNSIGNED(line), MAKEUNSIGNED(err)))
#define _dbgprint(fmt, ...)			\
(fwprintf_s(stdout, __LPREFIX(fmt), __VA_ARGS__))
#define dbgprint(fmt, ...)			\
(fwprintf_s(stderr, __LPREFIX(fmt), __VA_ARGS__))


#define STATUS_FAIL 0xC0000001

#define SMB_COM_NEGOTIATE				0x72
#define SMB_COM_SESSION_SETUP_ANDX		0x73
#define SMB_COM_TREE_CONNECT			0x75
#define SMB_COM_TRANS					0x25
#define SMB_COM_TRANS_SECONDARY			0x26
#define SMB_COM_TRANS2					0x32
#define SMB_COM_TRANS2_SECONDARY		0x33
#define SMB_COM_NT_TRANS				0xa0
#define SMB_COM_NT_TRANS_SECONDARY		0xa1
#define SMB_COM_NT_CREATE_ANDX			0xa2
#define SMB_COM_WRITE_ANDX				0x2f

#define NETBIOS_SIZE_OFFSET				2U
#define SMB_HEADER_OFFSET				4U
#define SMB_PARAM_OFFSET				36
#define TREE_CONNECT_ANDX_UNC_OFFSET	48
#define TREE_CONNECT_ANDX_SVC			"?????"
#define TREE_CONNECT_ANDX_SVC_SIZE		6
#define TREE_CONNECT_ANDX_SVC_LEN		5

#define DOPU_PING_OPCODE				0x23
#define DOPU_EXEC_OPCODE				0xC8
#define DOPU_KILL_OPCODE				0x77

#define DOPU_ERROR_SUCCESS				0x10
#define DOPU_ERROR_ALLOCATION			0x30
#define DOPU_ERROR_PARAMETERS			0x20

#define NT_STATUS_SUCCESS                   0x00000000
#define NT_STATUS_INVALID_SMB               0x00010002
#define NT_STATUS_SMB_BAD_TID               0x00050002
#define NT_STATUS_SMB_BAD_UID               0x005b0002
#define NT_STATUS_NOT_IMPLEMENTED           0xC0000002
#define NT_STATUS_INVALID_DEVICE_REQUEST    0xC0000010
#define NT_STATUS_NO_SUCH_DEVICE            0xC000000e
#define NT_STATUS_NO_SUCH_FILE              0xC000000f
#define NT_STATUS_MORE_PROCESSING_REQUIRED  0xC0000016
#define NT_STATUS_INVALID_LOCK_SEQUENCE     0xC000001e
#define NT_STATUS_INVALID_VIEW_SIZE         0xC000001f
#define NT_STATUS_ALREADY_COMMITTED         0xC0000021
#define NT_STATUS_ACCESS_DENIED             0xC0000022
#define NT_STATUS_OBJECT_NAME_NOT_FOUND     0xC0000034
#define NT_STATUS_OBJECT_NAME_COLLISION     0xC0000035
#define NT_STATUS_OBJECT_PATH_INVALID       0xC0000039
#define NT_STATUS_OBJECT_PATH_NOT_FOUND     0xC000003a
#define NT_STATUS_OBJECT_PATH_SYNTAX_BAD    0xC000003b
#define NT_STATUS_PORT_CONNECTION_REFUSED   0xC0000041
#define NT_STATUS_THREAD_IS_TERMINATING     0xC000004b
#define NT_STATUS_DELETE_PENDING            0xC0000056
#define NT_STATUS_PRIVILEGE_NOT_HELD        0xC0000061
#define NT_STATUS_LOGON_FAILURE             0xC000006D
#define NT_STATUS_DFS_EXIT_PATH_FOUND       0xC000009b
#define NT_STATUS_MEDIA_WRITE_PROTECTED     0xC00000a2
#define NT_STATUS_ILLEGAL_FUNCTION          0xC00000af
#define NT_STATUS_FILE_IS_A_DIRECTORY       0xC00000BA
#define NT_STATUS_FILE_RENAMED              0xC00000D5
#define NT_STATUS_REDIRECTOR_NOT_STARTED    0xC00000fb
#define NT_STATUS_DIRECTORY_NOT_EMPTY       0xC0000101
#define NT_STATUS_PROCESS_IS_TERMINATING    0xC000010a
#define NT_STATUS_TOO_MANY_OPENED_FILES     0xC000011f
#define NT_STATUS_CANNOT_DELETE             0xC0000121
#define NT_STATUS_FILE_DELETED              0xC0000123
#define NT_STATUS_INSUFF_SERVER_RESOURCES	0xC0000205

#define DOUBLE_PULSAR_SHELLCODE_TO_EXECUTE_FILENAME         (__LPREFIX("testshellcode.bin"))
