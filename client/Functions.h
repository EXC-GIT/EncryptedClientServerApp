#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma once
//input_output
#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h>

//Windows, Socket
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

//link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

//CryptoPP
#include <cryptopp/files.h>
#include <cryptopp/rsa.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/seed.h>
#include <cryptopp/hex.h>

//Standard C++ Library
using namespace std;
//CryptoPP
using namespace CryptoPP;

//SETUP SOCKET
int promptPort();
string promptIP();
bool validateIP(string ip);
bool cNum(string& str);
vector<string> split(const string& str, char delim);

//Get Information
void getpeerinfo(SOCKET);

//Saving key
void SavingKeysAndParams(PrivateKey&, PublicKey&, InvertibleRSAFunction&);
//checking key
int checkkeyexist();

//Hex Function
string hexstring(char*);
string hexdecode(string);

//Hash (return Hex form)
string HASH(string,HashTransformation&);

//Send Message
int sendMessage(SOCKET socket, string message, int len);

//MessageCryptoFunctions (CFB Mode)
//MessageCryptoEncryptFunctions (CFB Mode)
string Encrypt(string, CFB_Mode< SEED >::Encryption);
//MessageCryptoDecryptFunctions (CFB Mode)
string Decrypt(string, CFB_Mode< SEED >::Decryption);

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)  