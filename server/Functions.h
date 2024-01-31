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
#include "H:/Sem_4/Crypto/cryptopp/files.h"
#include "H:/Sem_4/Crypto/cryptopp/rsa.h"
#include "H:/Sem_4/Crypto/cryptopp/modes.h"
#include "H:/Sem_4/Crypto/cryptopp/osrng.h"
#include "H:/Sem_4/Crypto/cryptopp/files.h"
#include "H:/Sem_4/Crypto/cryptopp/sha.h"
#include "H:/Sem_4/Crypto/cryptopp/seed.h"
#include "H:/Sem_4/Crypto/cryptopp/hex.h"
#include "H:/Sem_4/Crypto/cryptopp/seed.h"

//Standard C++ Library
using namespace std;
//CryptoPP
using namespace CryptoPP;

//SETUP SOCKET
//promptPort
int promptPort();

//Save Function
void SavingKeysAndParams(PrivateKey&, PublicKey&, InvertibleRSAFunction&);
//checking key
int checkkeyexist();

//HASH (Param : string , hash function)
string HASH(string str, HashTransformation& hm);

//hex function ( return string )
string hexstring(char*);
//hex decoding ( return string )
string hexdecode(string);


//Send Message
int sendMessage(SOCKET socket, string message, int len);

//MessageCryptoFunctions (CFB Mode)
//MessageCryptoEncryptFunctions (CFB Mode)
string Encrypt(string, CFB_Mode< SEED >::Encryption);
//MessageCryptoDecryptFunctions (CFB Mode)
string Decrypt(string, CFB_Mode< SEED >::Decryption);



#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)  