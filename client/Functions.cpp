#include "Functions.h"



void getpeerinfo(SOCKET socket)
{
	sockaddr_in client_info;
	int addrsize = sizeof(client_info);

	// or get it from the socket itself at any time
	int result = getpeername(socket, (struct sockaddr*)&client_info, &addrsize);
	if (result == 0)
		cout << "Connected To: " << inet_ntoa(client_info.sin_addr) << endl;
	else
		cout << "Could not get host name: " << WSAGetLastError() << endl;
}


// For IPv4 Address
string promptIP()
{
	string ip;
	cout << "Enter Server IP: ";
	cin >> ip;
	cin.ignore(10000, '\n');

	while (!validateIP(ip))
	{
		cout << "Enter Valid Server IP: ";
		cin >> ip;
		cin.ignore(10000, '\n');
	}
	return ip;
}
// Validate an ipv4 address
bool validateIP(string ip) {
	// split the string 
	vector<string> slist = split(ip, '.');
	//if not 4 parts, means not an ipv4 address
	if (slist.size() != 4)
		return false;
	for (string str : slist) {
		// check content of splited string , check if between 0 -255 ( range )
		if (!cNum(str) || stoi(str) < 0 || stoi(str) > 255)
			return false;
	}
	return true;
}
// Check if the given string is a numeric string or not
bool cNum(string& str) {
	return !str.empty() && (str.find_first_not_of("[0123456789]") == std::string::npos);
}
// Function to split string str using given delimiter
vector<string> split(const string& str, char delim) {
	auto i = 0;
	vector<string> list;
	auto pos = str.find(delim);
	while (pos != string::npos) {
		list.push_back(str.substr(i, pos - i));
		i = ++pos;
		pos = str.find(delim, pos);
	}
	list.push_back(str.substr(i, str.length()));
	return list;
}
// Port Number for the application
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

//saving key
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

//hash SHA1
string HASH(string str , HashTransformation& hm)
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
string Encrypt(string x, CFB_Mode< SEED >::Encryption e)
{
	string temp = hexstring((char*)&x[0]), enc = "";
	StringSource encryptMsg(temp, true, new StreamTransformationFilter(e, new StringSink(enc)));
	enc = hexstring(&enc[0]);
	return enc;
}
string Decrypt(string x, CFB_Mode< SEED >::Decryption d)
{
	string temp = hexdecode(x), dec = "";
	StringSource decryptMsg(temp, true, new StreamTransformationFilter(d, new StringSink(dec)));
	dec = hexdecode(dec);
	return dec;
}
