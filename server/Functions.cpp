#include "Functions.h"


//prompt user for port number
int promptPort()
{
	int port;
	cout << "Enter Port Number ( 1 - 65535 ): ";
	cin >> port;
	cin.ignore(10000, '\n');

	while (cin.fail() || port < 1 || port > 65535)
	{
		cin.clear();
		cin.ignore(10000, '\n');
		cout << "Invalid port number.\n"
			<< "Enter valid port number ( 1 - 65535 ): ";
		cin >> port;
		cin.ignore(10000, '\n');
	}
	return port;
}

//Save Function
void SavingKeysAndParams(PrivateKey& privatekey, PublicKey& publickey, InvertibleRSAFunction& params)
{
	publickey.Save(
		FileSink(string("host.publickey").c_str(), true).Ref()
	);
	privatekey.Save(
		FileSink(string("host.privatekey").c_str(), true).Ref()
	);
	params.Save(
		FileSink(string("key.params").c_str(), true).Ref()
	);
}
//checking key exist
int checkkeyexist()
{
	struct stat buffer;
	if (stat(string("host.privatekey").c_str(), &buffer) == 0)
	{
		cout << "Private Key Found..." << endl;
	}
	else
	{
		return 1;
	}
	buffer = {};
	if (stat(string("host.publickey").c_str(), &buffer) == 0)
	{
		cout << "Private Key Found..." << endl;
	}
	else
	{
		return 1;
	}
	buffer = {};
	if (stat(string("key.params").c_str(), &buffer) == 0)
	{
		cout << "Key Parameters Found..." << endl;
	}
	else
	{
		return 1;
	}
	return 0;
}

//HexEncode
string hexstring(char* str)
{
	string temp = "";
	StringSource hexstring(str, true, new HexEncoder(new StringSink(temp)));
	return temp;
}
//HexDecode
string hexdecode(string str)
{
	string temp = "";
	StringSource decodeHex(str, true, new HexDecoder(new StringSink(temp)));
	return temp;
}

//HASH
string HASH(string str, HashTransformation& hm)
{
	string temp = "";
	StringSource hash(str, true, new HashFilter(hm, new HexEncoder(new StringSink(temp))));
	return temp;
}

//send message
int sendMessage(SOCKET socket, string message, int len)
{
	int result;
	result = send(socket, message.c_str(), len, 0);
	if (result == SOCKET_ERROR) {
		printf("Message send failed with error: %d\n", WSAGetLastError());
		closesocket(socket);
		WSACleanup();
		return 1;
	}
	return 0;
}

//MessageCryptoFunctions (CFB Mode)
string Encrypt(string x , CFB_Mode< SEED >::Encryption e)
{
	string temp = hexstring((char*)&x[0]) , enc = "";
	StringSource encryptMsg(temp, true, new StreamTransformationFilter(e, new StringSink(enc)));
	enc = hexstring(&enc[0]);
	return enc;
}
string Decrypt(string x, CFB_Mode< SEED >::Decryption d)
{
	string temp = hexdecode(x) , dec = "";
	StringSource decryptMsg(temp, true, new StreamTransformationFilter(d, new StringSink(dec)));
	dec = hexdecode(dec);
	return dec;
}