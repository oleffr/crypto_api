#define WIN32_LEAN_AND_MEAN 
#include <windows.h> 
#include <winsock2.h> 
#include <ws2tcpip.h> // Директива линковщику: использовать библиотеку сокетов 
#pragma comment(lib, "ws2_32.lib") 
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#include<string.h>
#include <conio.h>
#pragma warning(disable : 4996)

#include <iostream>
#include <string>
#include <vector>

#define MAX_COMMAND_SIZE 500
#define MAX_BUFFER_SIZE 2048
#define KEY_BUF_SIZE 256
#define MIN_PATH_SIZE 5

using namespace std;

typedef struct sock
{
	int s;
	HCRYPTPROV DescCSP;
	HCRYPTKEY DescKey;
	HCRYPTKEY DescKey_imp;
	HCRYPTKEY hPublicKey, hPrivateKey;

}socketExtended;

vector<socketExtended> sockets;
void Menu() {
	printf("_______________________________________________________________\n");
	printf("Select the command:\n");
	printf("add_server - добавить сервер\n");
	printf("version - тип и версия ОС\n");
	printf("cur_time - текущее время\n");
	printf("boot_time - время с запуска ОС сервера\n");
	printf("memory - информация о хранилище\n");
	printf("storage - подключенные диски\n");
	printf("rights - права доступа к директории *\n");
	printf("owner - владелец директории *\n");
	printf("help - списк команд\n");
	printf("quit - отключить клиент от сервера\n");
	printf("\n* = после команды необходимо добавить директорию\n");
	printf("_______________________________________________________________\n");
}
int init()
{
	// Для Windows следует вызвать WSAStartup перед началом использования сокетов 
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
}

void s_close(int s)
{
	closesocket(s);
}

//ошибки сокетов
int sock_err(const char* function, int s)
{
	int err;
	err = WSAGetLastError();
	fprintf(stderr, "%s: socket error: %d\n", function, err);
	return -1;
}

//10 попыток подключения, 100 мс ждем
int connect_100ms(int s, struct sockaddr_in addr)
{
	for (int rec = 0; rec < 10; rec++)
	{
		if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
			return 0;
		else
		{
			fprintf(stdout, "%i time failed to connect to server\n", (rec + 1));
			Sleep(100);
		}
	}
	return 1;
}

//считает длину строки
unsigned int strLength(char* mas, int startPos)
{
	int i = startPos;
	for (int j = startPos - 1; j >= 0; j--)
	{
		if (mas[j] != '\0') break;
		else i--;
	}
	return i;
}

int crytp_send(int choiceSize, char* buffer, unsigned int& bufSize, int s, char* choice)
{
	if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
		printf("ERROR, %x", GetLastError());

	if (send(sockets[s].s, choice, choiceSize, 0) < 0)
		return sock_err("send", sockets[s].s);
	if (recv(sockets[s].s, buffer, MAX_BUFFER_SIZE, 0) < 0)
		return sock_err("receive", sockets[s].s);

	bufSize = strLength(buffer, MAX_BUFFER_SIZE);
	if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)buffer, (DWORD*)&bufSize))
		printf("ERROR, %x", GetLastError());
	return 1;
}

int CryptReal(int s, sockaddr_in addr)
{
	socketExtended result;

	/*Для создания контейнера ключей с определенным CSP
	 phProv – указатель а дескриптор CSP.
	 pszContainer – имя контейнера ключей.
	 pszProvider – имя CSP.
	 dwProvType – тип CSP.
	 dwFlags – флаги.*/

	 /* Создает новый контейнер ключей с именем, указанным в pszContainer .
	 Если pszContainer имеет значение NULL , создается контейнер ключей с именем по умолчанию. */

	if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			printf("ERROR, %x", GetLastError());
	}

	/* Функция экспорта ключа для его передачи по каналам информации.
	   Возможны различные варианты передачи ключа, включая передачу публичного ключа, пары ключей, а также передачу секретного или сеансового ключа
		hProv– дескриптор CSP.
		Algid – идентификатор алгоритма(указываем, что генерируем пару ключей, а не подпись).
		dwFlags – флаги.
		phKey – указатель на дескриптор ключа.*/

	if (CryptGenKey(result.DescCSP, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &result.DescKey) == 0)
		printf("ERROR, %i", GetLastError());

	//Клиент генерирует асимметричный ключ–пару ключей публичный/приватный

	if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPublicKey))
		printf("CryptGetUserKey err\n");
	if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPrivateKey))
		printf("CryptGetUserKey err\n");

	char ExpBuf[KEY_BUF_SIZE] = { 0 };
	DWORD len = KEY_BUF_SIZE;

	/* Клиент посылает публичный ключ серверу (2й аргумент - 0, тк мы не шифруем посылаемый публичный ключ)
	   hKey – дескриптор экспортируемого ключа.
	   hExpKey – ключ, с помощью которого будет зашифрован hKey при экспорте.
	   dwBlobType – тип экспорта.
	   dwFlags – флаги.
	   pbData – буфер для экспорта. Будет содержать зашифрованный hKey с помощью hExpKey.
	   pdwDataLen – длина буфера на вход. На выходе – количество значащих байт */

	if (!CryptExportKey(result.hPublicKey, 0, PUBLICKEYBLOB, NULL, (BYTE*)ExpBuf, &len))
		printf("ERROR, %x", GetLastError());

	//передаём длину ключа
	int expBufSize = strLength(ExpBuf, KEY_BUF_SIZE);
	ExpBuf[expBufSize] = expBufSize;

	//отправка - получение информации
	if (send(s, ExpBuf, (expBufSize + 1), 0) < 0)
		sock_err("send", s);
	char buffer[KEY_BUF_SIZE] = { 0 };
	if (recv(s, buffer, KEY_BUF_SIZE, 0) < 0)
		sock_err("receive", s);

	int bufSize = strLength(buffer, KEY_BUF_SIZE) - 1;
	unsigned int dli = (unsigned char)buffer[bufSize];
	buffer[bufSize] = 0;

	/* Клиент получает зашифрованное сообщение и расшифровывает его с помощью своего приватного ключа (Функция предназначена для получения из каналов информации значения ключа)
	   hProv – дескриптор CSP.
	   pbData – импортируемый ключ представленный в виде массива байт.
	   dwDataLen –длина данных в pbData.
	   hPubKey - дескриптор ключа, который расшифрует ключ содержащийся в pbData.
	   dwFlags - флаги.
	   phKey – указатель на дескриптор ключа. Будет указывать на импортированный ключ */

	if (!CryptImportKey(result.DescCSP, (BYTE*)buffer, dli, result.hPrivateKey, 0, &result.DescKey_imp))//получаем сеансовый ключ
		printf("ERROR, %x", GetLastError());
	result.s = s;
	sockets.push_back(result);

	return s;
}

//вводимая команда
void input_str(char* choiceStr, char* choice)
{
	char temp[MAX_COMMAND_SIZE];
	int i = 0;
	int indexM = -1;
	for (; i < strlen(choiceStr); i++)
	{
		if (choiceStr[i] == ' ')
		{
			indexM = i;
			break;
		}

		temp[i] = choiceStr[i];
		temp[i + 1] = '\0';
	}

	if (strcmp(temp, "help") == 0)
	{
		choice[0] = 'h';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "add_server") == 0)
	{
		choice[0] = 'a';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "version") == 0)
	{
		choice[0] = 'o';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "cur_time") == 0)
	{
		choice[0] = 't';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "boot_time") == 0)
	{
		choice[0] = 'm';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "storage") == 0)
	{
		choice[0] = 'f';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "memory") == 0)
	{
		choice[0] = 's';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "close_client") == 0)
	{
		choice[0] = 'e';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "quit") == 0)
	{
		choice[0] = 'q';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "rights") == 0)
	{
		choice[0] = 'p';
		choice[1] = ' ';
	}
	if (strcmp(temp, "owner") == 0)
	{
		choice[0] = 'r';
		choice[1] = ' ';
	}
	int j = 0;
	for (i = 2, j = indexM + 1; j < strlen(choiceStr); i++, j++)
	{
		choice[i] = choiceStr[j];
		choice[i + 1] = '\0';
	}
	return;
}

//добавляем новый сокет
int addNewSocket()
{
	cout << "Enter ip:port\n";
	string ipAddrAndPort = "";
	cin >> ipAddrAndPort;
	string ipAddress = ipAddrAndPort.substr(0, ipAddrAndPort.find(":"));
	string port = ipAddrAndPort.substr(ipAddrAndPort.find(":") + 1);

	if (port.size() == 0)
		return sock_err("finding the port", 0);

	int s;
	struct sockaddr_in addr;
	short num_port = (short)atoi(port.c_str());

	// Инициалиазация сетевой библиотеки 
	// Для Windows следует вызвать WSAStartup перед началом использования сокетов 
	WSADATA wsa_data;
	init();

	// Создание TCP-сокета 
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return sock_err("socket", s);

	// Заполнение структуры с адресом удаленного узла 
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(num_port);
	addr.sin_addr.s_addr = inet_addr(ipAddress.c_str());

	// Попытка установить соединение 
	if (connect_100ms(s, addr) != 0)
	{
		s_close(s);
		return sock_err("connect", s);
	}
	cout << "Connecting to the server!" << endl;

	//шифрование
	s = CryptReal(s, addr);
	cout << "Socket number: " << sockets.size() << endl;

	return s;
}

int io_serv() {
	char buffer[MAX_BUFFER_SIZE] = { 0 };
	char choice[MAX_COMMAND_SIZE];
	char choiceStr[MAX_COMMAND_SIZE];
	char socketNumStr[MAX_COMMAND_SIZE];

	unsigned int choiceSize;
	unsigned int bufSize;
	bool start = true;

	int s = 0;//current socket
	cout << "Successful start work \n ";
	do {
		memset(buffer, 0, MAX_BUFFER_SIZE);
		memset(choice, 0, MAX_COMMAND_SIZE);
		if (!start)
			cout << "Enter connection number : ";
		else {
			addNewSocket();
			start = false;
			printf("Enter connection number : ");
		}

		scanf("%d", &s);
		char sym;
		scanf("%c", &sym);

		if (s > 0) {
			s--;
			scanf("%[^\n]", choiceStr);
			input_str(choiceStr, choice);
			choiceSize = strlen(choice);

			switch (choice[0])
			{
			case 'o':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;
				cout << endl << buffer << endl;
				break;
			}

			case 't':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;
				cout << endl << buffer << endl;
				break;
			}

			case 'm':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;
				cout << endl << buffer << endl;
				break;
			}

			case 's':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;
				cout << endl << buffer << endl;
				break;
			}

			case 'f':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;

				cout << endl << buffer << endl;
				break;
			}

			case 'p':
			{
				if (choiceSize < MIN_PATH_SIZE)
				{
					cout << "Incorrect path" << endl;
					break;
				}
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;
				cout << buffer << endl;
				break;
			}

			case 'r':
			{
				if (choiceSize < MIN_PATH_SIZE)
				{
					cout << "Incorrect path" << endl;
					break;
				}
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;
				cout << endl << buffer << endl;
				break;
			}

			case 'h':
			{
				Menu();
				continue;
			}

			case 'a':
			{
				addNewSocket();
				break;
			}

			case 'e':
			{
				if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
					printf("ERROR, %x", GetLastError());

				if (send(sockets[s].s, choice, strlen(choice), 0) < 0)
					return sock_err("send", sockets[s].s);

				if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)choice, (DWORD*)&choiceSize))
					printf("ERROR, %x", GetLastError());
				break;
			}

			case 'q':
			{
				goto END;
			}

			default:
			{
				printf("Incorrect command!\n");
				continue;
			}

			}
		}

	} while (choice[0] != 'q');

END:
	cout << "The connection is closed" << endl;
	closesocket(s);
	WSACleanup();
	return 0;
}

int main() {
	setlocale(LC_ALL, "Russian");
	return io_serv();
}