#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <time.h>
#include <sddl.h>
#include <wchar.h>
#include <mswsock.h>
#include <aclapi.h>
#include <lmcons.h>
#include <vector>
#include <chrono>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma warning(disable: 4996)

#define MAX_CLIENTS (100)
#define CLIENT_TIME 180
#define WIN32_LEAN_AND_MEAN

using namespace std;

int g_accepted_socket;
HANDLE g_io_port;
struct acl
{
	string name;
	char* sid;
	DWORD mask;
	vector<string> ace;
	bool inherit;
};

struct client_ctx
{
	int socket;
	CHAR buf_recv[512]; // Буфер приема
	CHAR buf_send[2048]; // Буфер отправки
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено
	// Структуры OVERLAPPED для уведомлений о завершении
	//позволяет	определить, какая именно операция была завершена
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv

	DWORD time;

	HCRYPTPROV DescCSP = 0;
	HCRYPTKEY DescKey = 0;
	HCRYPTKEY DescKey_open = 0;
};

// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];

// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			g_ctxs[i].time = clock();
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, * remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, (struct sockaddr**)&local_addr, &local_addr_sz, (struct sockaddr**)&remote_addr, &remote_addr_sz);
			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf("Connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);
			g_ctxs[i].socket = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. 
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct	sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

//Проверка на то, что строка пришла полностью, длина строки в len
int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{
		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	return 1;
}

void crypt_keys(int idx)
{
	// для создания контейнера ключей с определенным CSP
	/*phProv – указатель а дескриптор CSP.
	  pszContainer – имя контейнера ключей.
	  pszProvider – имя CSP.
	  dwProvType – тип CSP.
	  dwFlags – флаги.*/
	if (!CryptAcquireContextW(&g_ctxs[idx].DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL))
	{
		if (!CryptAcquireContextW(&g_ctxs[idx].DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, (CRYPT_NEWKEYSET)))
			printf("ERROR, %x", GetLastError());
	}

	//Данная функция предназначена для генерации сеансового ключа, а также для\
	генерации пар ключей для обмена и цифровой подписи
	/*
	hProv– дескриптор CSP.
	Algid – идентификатор алгоритма.
	dwFlags – флаги.
	phKey – указатель на дескриптор ключа.
	*/
	if (CryptGenKey(g_ctxs[idx].DescCSP, CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), &g_ctxs[idx].DescKey) == 0)
		printf("ERROR, %x", GetLastError());

	//Сервер получает публичный ключ клиента
	//сачала достаём длину ключа
	/*
	hProv – дескриптор CSP.
	pbData – импортируемый ключ представленный в виде массива байт.
	dwDataLen –длина данных в pbData.
	hPubKey - дескриптор ключа, который расшифрует ключ содержащийся в pbData.
	dwFlags - флаги.
	phKey – указатель на дескриптор ключа. Будет указывать на импортированный ключ
	*/
	int i = 255;
	for (; i >= 0 && g_ctxs[idx].buf_recv[i] == 0;)	i--;
	unsigned int len = (unsigned char)g_ctxs[idx].buf_recv[i];
	g_ctxs[idx].buf_recv[i] = 0;
	if (!CryptImportKey(g_ctxs[idx].DescCSP, (BYTE*)g_ctxs[idx].buf_recv, len, 0, 0, &g_ctxs[idx].DescKey_open))//получаем открытый ключ
		printf("ERROR, %x", GetLastError());

	//CryptExportKey - Функция экспорта ключа для его передачи по каналам информации.\
	Возможны различные варианты передачи ключа, включая передачу публичного ключа,\
	пары ключей, а также передачу секретного или сеансового ключа.
	//Сервер шифрует сеансовый ключ публичным ключом клиента и отправляет
	//получившееся зашифрованное сообщение клиенту
	/*
	hKey – дескриптор экспортируемого ключа.
	hExpKey – ключ, с помощью которого будет зашифрован hKey при экспорте.
	dwBlobType – тип экспорта.
	dwFlags – флаги.
	pbData – буфер для экспорта. Будет содержать зашифрованный hKey с помощью
	hExpKey.
	pdwDataLen – длина буфера на вход. На выходе – количество значащих байт
	*/
	DWORD lenExp = 256;
	if (!CryptExportKey(g_ctxs[idx].DescKey, g_ctxs[idx].DescKey_open, SIMPLEBLOB, NULL, (BYTE*)g_ctxs[idx].buf_send, &lenExp))//шифруем сеансовый ключ открытым
		printf("ERROR, %x", GetLastError());
	g_ctxs[idx].buf_send[lenExp] = lenExp;
	g_ctxs[idx].sz_send_total = lenExp + 1;
}

string AceType(short t)
{
	switch (t)
	{
	case 0: return "ACCESS_ALLOWED_ACE_TYPE ";
	case 1: return "ACCESS_ALLOWED_CALLBACK_ACE_TYPE ";
	case 2: return "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE ";
	case 3: return "ACCESS_ALLOWED_COMPOUND_ACE_TYPE ";
	case 4: return "ACCESS_ALLOWED_OBJECT_ACE_TYPE ";
	case 5: return "ACCESS_DENIED_ACE_TYPE ";
	case 6: return "ACCESS_DENIED_CALLBACK_ACE_TYPE ";
	case 7: return "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE ";
	case 8: return "ACCESS_DENIED_OBJECT_ACE_TYPE ";
	case 9: return "ACCESS_MAX_MS_ACE_TYPE ";
	case 10: return "ACCESS_MAX_MS_V2_ACE_TYPE ";
	case 11: return "ACCESS_MAX_MS_V3_ACE_TYPE ";
	case 12: return "ACCESS_MAX_MS_V4_ACE_TYPE ";
	case 13: return "ACCESS_MAX_MS_OBJECT_ACE_TYPE ";
	case 14: return "ACCESS_MIN_MS_ACE_TYPE ";
	case 15: return "ACCESS_MIN_MS_OBJECT_ACE_TYPE ";
	case 16: return "SYSTEM_ALARM_ACE_TYPE ";
	case 17: return "SYSTEM_ALARM_CALLBACK_ACE_TYPE ";
	case 18: return "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE ";
	case 19: return "SYSTEM_ALARM_OBJECT_ACE_TYPE ";
	case 20: return "SYSTEM_AUDIT_ACE_TYPE ";
	case 21: return "SYSTEM_AUDIT_CALLBACK_ACE_TYPE ";
	case 22: return "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE ";
	case 23: return "SYSTEM_AUDIT_OBJECT_ACE_TYPE ";
	case 24: return "SYSTEM_MANDATORY_LABEL_ACE_TYPE ";
	default: return "Unknown type of ACE ";
	}
}

void menu(DWORD idx)
{
	DWORD count = 0;

	if (g_ctxs[idx].DescCSP != 0 && g_ctxs[idx].DescKey != 0 && g_ctxs[idx].DescKey_open != 0)
	{
		count = g_ctxs[idx].sz_recv;
		if (!CryptDecrypt(g_ctxs[idx].DescKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[idx].buf_recv, (DWORD*)&count))
			printf("ERROR, %x", GetLastError());
	}

	switch (g_ctxs[idx].buf_recv[0])
	{
	case 'o':
	{
		DWORD bufsize = 100;
		CHAR version[100];
		HKEY hKey; //адрес переменной, в которую возвращается дескриптор открытого ключа

		//открывает указанный ключ, *адрес строки, содержащей имя ключа на открытие*права запрашивать данные подключей*
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
		{
			// получает значение параметра из раздела реестра
			RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)version, &bufsize);
			strcpy(g_ctxs[idx].buf_send, version);
		}
		break;
	}
	case 't':
	{
		DWORD len = 2048;
		auto time_now = std::chrono::system_clock::now();
		time_t time = std::chrono::system_clock::to_time_t(time_now);
		string times(std::ctime(&time));
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], times.c_str());
		cout << g_ctxs[idx].buf_send;
		break;
	}
	case 'm':
	{
		DWORD len = 2048;
		auto ms = std::chrono::milliseconds(GetTickCount64());
		auto secs = std::chrono::duration_cast<std::chrono::seconds>(ms);
		ms -= std::chrono::duration_cast<std::chrono::milliseconds>(secs);
		auto mins = std::chrono::duration_cast<std::chrono::minutes>(secs);
		secs -= std::chrono::duration_cast<std::chrono::seconds>(mins);
		auto hour = std::chrono::duration_cast<std::chrono::hours>(mins);
		mins -= std::chrono::duration_cast<std::chrono::minutes>(hour);
		std::string s(std::to_string(hour.count()) + " hours " + std::to_string(mins.count()) + " mins " + std::to_string(secs.count()) + " secs " + std::to_string(ms.count()) + " ms");

		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], s.c_str());
		break;
	}
	case 's':
	{
		MEMORYSTATUSEX state;
		state.dwLength = sizeof(state);
		GlobalMemoryStatusEx(&state);

		string result("Memory Load: " + std::to_string(state.dwMemoryLoad) + " %\n" + "Total Physical Memory: " + std::to_string((double)state.ullTotalPhys / 1024.0 / 1024.0) + " MB\n"
			+ "Available Physical Memory: " + std::to_string((double)state.ullAvailPhys / 1024.0 / 1024.0) + " MB\n" + "Total Page Memory: " + std::to_string((double)state.ullTotalPageFile / 1024.0 / 1024.0) + " MB\n"
			+ "Available Page Memory: " + std::to_string((double)state.ullAvailPageFile / 1024.0 / 1024.0) + " MB\n" + "Total Virtual Memory: " + std::to_string((double)state.ullTotalVirtual / 1024.0 / 1024.0) + " MB\n"
			+ "Available Virtual Memory: " + std::to_string((double)state.ullAvailVirtual / 1024.0 / 1024.0) + " MB\n");

		strcpy(g_ctxs[idx].buf_send, result.c_str());
		break;
	}
	case 'f':
	{

		DWORD dr = GetLogicalDrives();
		char disks[26][4] = { 0 };
		char FileSystem[10];
		DWORD sectors, bytes, free_clusters, clusters;
		int disk_count = 0;
		for (int i = 0; i < 26; i++)
		{
			if ((dr & (1 << i)))
			{
				disks[disk_count][0] = char(65 + i);
				disks[disk_count][1] = ':';
				disks[disk_count][2] = '\\';
				disk_count++;
			}
		}

		std::string s;
		for (int i = 0; i < disk_count; i++)
		{
			s += disks[i];
			s += " ";
			switch (GetDriveTypeA((LPSTR)disks[i]))
			{
			case 0:
				s += "Unknown ";
				break;
			case 1:
				s += "Invalid Root Path ";
				break;
			case 2:
				s += "Removable ";
				break;
			case 3:
				s += "HDD ";
				break;
			case 4:
				s += "Remote ";
				break;
			case 5:
				s += "CD ";
				break;
			case 6:
				s += "RAM ";
				break;
			default:
				break;
			}
			//файловая система
			GetVolumeInformationA((LPSTR)disks[i], NULL, NULL, NULL, NULL, NULL, FileSystem, 10);
			if (!strcmp(FileSystem, "NTFS"))
				s += "NTFS ";
			if (!strcmp(FileSystem, "FAT"))
				s += "FAT ";
			if (!strcmp(FileSystem, "CDFS"))
				s += "CDFS ";

			//свободное место
			GetDiskFreeSpaceA((LPSTR)disks[i], &sectors, &bytes, &free_clusters, &clusters);
			s += "Free Space: ";
			s += std::to_string((double)free_clusters * (double)sectors * (double)bytes / 1024.0 / 1024.0 / 1024.0);
			s += " GB\n";
		}
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], s.c_str());
		break;
	}
	case 'p':
	{
		byte p[2048];
		size_t i = 0;
		for (i = 0; i < strlen(g_ctxs[idx].buf_recv) - 2; i++)
			p[i] = g_ctxs[idx].buf_recv[i + 2];
		p[i] = '\0';

		PACL dacl;
		PSID sidowner = NULL;
		PSID sidgroup = NULL;
		PSECURITY_DESCRIPTOR sec;
		DWORD owner_name_len = UNLEN;
		DWORD domain_name_len = UNLEN;
		LPSTR owner_name = (LPSTR)LocalAlloc(GMEM_FIXED, owner_name_len);
		LPSTR domain_name = (LPSTR)LocalAlloc(GMEM_FIXED, domain_name_len);
		SID_NAME_USE peUse;
		LPVOID ace;
		GetNamedSecurityInfoA((LPCSTR)p, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			GetNamedSecurityInfoA((LPCSTR)p, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			return;
		LookupAccountSidA(NULL, sidowner, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
		SID* sid = NULL;
		unsigned long mask;
		std::vector<acl> access_control_list;
		for (int i = 0; i < (*dacl).AceCount; i++)
		{
			acl access_control;
			GetAce(dacl, i, &ace);
			ACCESS_ALLOWED_ACE* ace_2 = (ACCESS_ALLOWED_ACE*)ace;
			owner_name_len = UNLEN;
			domain_name_len = UNLEN;
			if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceFlags)
				access_control.inherit = true;
			else
				access_control.inherit = false;
			if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
			{
				sid = (SID*)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
				LookupAccountSidA(NULL, sid, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
				access_control.name = std::string(owner_name);
				access_control.ace.push_back(string("Allow:"));
				mask = ((ACCESS_ALLOWED_ACE*)ace)->Mask;
			}
			else if (((ACCESS_DENIED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
			{
				sid = (SID*)&((ACCESS_DENIED_ACE*)ace)->SidStart;
				LookupAccountSidA(NULL, sid, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
				access_control.name = std::string(owner_name);
				access_control.ace.push_back(string("Deny:"));
				mask = ((ACCESS_DENIED_ACE*)ace)->Mask;
			}

			std::string ace_name;

			if (DELETE & ace_2->Mask)
			{
				ace_name = "Delete";
				access_control.ace.push_back(ace_name);
			}
			if (FILE_GENERIC_READ & ace_2->Mask)
			{
				ace_name = "File Generic Read";
				access_control.ace.push_back(ace_name);
			}
			if (FILE_GENERIC_WRITE & ace_2->Mask)
			{
				ace_name = "File Generic Write";
				access_control.ace.push_back(ace_name);
			}
			if (FILE_GENERIC_EXECUTE & ace_2->Mask)
			{
				ace_name = "File Generic Execute";
				access_control.ace.push_back(ace_name);
			}
			if (GENERIC_READ & ace_2->Mask)
			{
				ace_name = "Generic Read";
				access_control.ace.push_back(ace_name);
			}
			if (GENERIC_WRITE & ace_2->Mask)
			{
				ace_name = "Generic Write";
				access_control.ace.push_back(ace_name);
			}
			if (GENERIC_EXECUTE & ace_2->Mask)
			{
				ace_name = "Generic Execute";
				access_control.ace.push_back(ace_name);
			}
			if (GENERIC_ALL & ace_2->Mask)
			{
				ace_name = "Generic All";
				access_control.ace.push_back(ace_name);
			}
			if (READ_CONTROL & ace_2->Mask)
			{
				ace_name = "Read Control";
				access_control.ace.push_back(ace_name);
			}
			if (WRITE_DAC & ace_2->Mask)
			{
				ace_name = "Write DAC";
				access_control.ace.push_back(ace_name);
			}
			if (WRITE_OWNER & ace_2->Mask)
			{
				ace_name = "Write Owner";
				access_control.ace.push_back(ace_name);
			}
			if (SYNCHRONIZE & ace_2->Mask)
			{
				ace_name = "Synchronize";
				access_control.ace.push_back(ace_name);
			}
			access_control_list.push_back(access_control);
			access_control_list[i].mask = ace_2->Mask;
			ConvertSidToStringSidA(sid, &access_control_list[i].sid);
		}

		std::string s;
		for (int i = 0; i < access_control_list.size(); i++)
		{

			s += access_control_list[i].name;
			s += " ";
			s += access_control_list[i].sid;
			s += " ";
			char tmp[100] = { 0 };
			ltoa(access_control_list[i].mask, tmp, 2);
			s += tmp;
			s += " ";
			s += access_control_list[i].ace.front();
			for (int j = 1; j < access_control_list[i].ace.size(); j++)
			{
				s += access_control_list[i].ace[j];
				s += ";";
			}
			s += '\n';
		}
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], s.c_str());

		break;
	}
	case 'r':
	{
		byte p[2048];
		size_t i = 0;
		for (i = 0; i < strlen(g_ctxs[idx].buf_recv) - 2; i++)
			p[i] = g_ctxs[idx].buf_recv[i + 2];
		p[i] = '\0';

		PACL dacl;
		PSID sidowner = NULL;
		PSID sidgroup = NULL;
		PSECURITY_DESCRIPTOR sec;
		DWORD owner_name_len = UNLEN;
		DWORD domain_name_len = UNLEN;
		LPSTR owner_name = (LPSTR)LocalAlloc(GMEM_FIXED, owner_name_len);
		LPSTR domain_name = (LPSTR)LocalAlloc(GMEM_FIXED, domain_name_len);
		SID_NAME_USE peUse;
		GetNamedSecurityInfoA((LPCSTR)p, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			GetNamedSecurityInfoA((LPCSTR)p, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			return;

		LookupAccountSidA(NULL, sidowner, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
		std::string s(owner_name);
		s += " ";
		char* tmp;
		ConvertSidToStringSidA(sidowner, &tmp);
		s += tmp;
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], s.c_str());
		break;
	}
	case 'e':
	{
		g_ctxs[idx].DescCSP = 0;
		g_ctxs[idx].DescKey = 0;
		g_ctxs[idx].DescKey_open = 0;
		memset(g_ctxs[idx].buf_send, 0, 2048);
		CancelIo((HANDLE)g_ctxs[idx].socket);
		PostQueuedCompletionStatus(g_io_port, 0, idx, &g_ctxs[idx].overlap_cancel);
		return;
	}
	default:
	{
		crypt_keys(idx);
		return;
	}
	}

	count = strlen(g_ctxs[idx].buf_send);
	if (!CryptEncrypt(g_ctxs[idx].DescKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[idx].buf_send, (DWORD*)&count, 2048))
		printf("ERROR, %x", GetLastError());
	g_ctxs[idx].sz_send_total = count;
}

void io_serv()
{
	//инициализация интерфейса сокетов
	//аргументы: версия интрфейса, структура для записи сведений
	//о конкретной реализации интерфейса Windows Sockets
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}

	struct sockaddr_in addr;

	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	//INVALID_HANDLE_VALUE означает то, что нам нужен новый порт
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}

	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;		//iPv4
	addr.sin_port = htons(1234);
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n");
		return;
	}
	printf("Listening: %hu\n", ntohs(addr.sin_port));

	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;

	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях
	int flag = 0;
	while (1)
	{
		DWORD transferred;		//указатель на переменнную, в которую запишется количество переданных байт в результате завершения операции (фактически это возвращаемое значение recv() и send() в синхронном режиме)
		ULONG_PTR key;			//
		OVERLAPPED* lp_overlap;	//указатель на OVERLAPPED, ассоциированную с этой IO-транзакцией
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						CancelIo((HANDLE)g_ctxs[key].socket);
						//Функция помещает в очередь порта сообщение
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						// Если строка полностью пришла, то сформировать ответ и начать его отправлять
						menu(key);
						g_ctxs[key].time = clock();
						g_ctxs[key].sz_send = 0;
						memset(g_ctxs[key].buf_recv, 0, 512);
						schedule_write(key);
					}
					else
					{
						// Иначе - ждем данные дальше
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						g_ctxs[key].sz_recv = 0;
						memset(g_ctxs[key].buf_send, 0, 2048);
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf("The connection is closed\n", key);
				}
			}
		}
		else
		{
			// Если не произошло никаких событий, сервер ищет клиентов
			// от которых не было действий более WAIT_SECONDS секунд
			for (int counter = 1; counter < MAX_CLIENTS; counter++)
			{
				if (g_ctxs[counter].socket != 0 && (clock() - g_ctxs[counter].time) / CLOCKS_PER_SEC >= CLIENT_TIME)
				{
					CancelIo((HANDLE)g_ctxs[counter].socket);
					PostQueuedCompletionStatus(g_io_port, 0, counter, &g_ctxs[counter].overlap_cancel);
				}
			}
		}
	}
}

int main()
{
	setlocale(LC_ALL, "Russian");
	io_serv();
	return 0;
}