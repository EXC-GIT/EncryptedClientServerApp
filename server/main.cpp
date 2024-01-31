
/*Reference: 
	- cryptopp wiki
	- visual studio from microsoft
	- binary tides
	- GeeksforGeeks
*/

#include "Functions.h"
//line function
inline void l()
{
	cout << "*--------------------------------------------------------------------------------------------------*" << endl;
}

// main 
int main()
{
	//Key Generation
	AutoSeededRandomPool rng;
	InvertibleRSAFunction params;
	RSA::PrivateKey privatekey;
	RSA::PublicKey publickey;


	int keyGen;
	if (checkkeyexist() == 0)
	{
		cout << "Complete RSA key found in directory." << endl;
		cout << "Use Old or Genearate New ( 1 / 2 ) -- (Old key will be replaced) : ";
		cin >> keyGen;
		cin.ignore(10000, '\n');

		while (cin.fail() || keyGen < 1 || keyGen >2)
		{
			cin.clear();
			cin.ignore(10000, '\n');
			cout << "1 - Using Old Existing Key \n"
				<< "2 - Generate New Key (Old key will be replaced) \n";
			cout << "Option : ";
			cin >> keyGen;
			cin.ignore(10000, '\n');
		}
		if (keyGen == 1)
		{
			cout << "Loading Component ..." << endl;
			publickey.Load(
				FileSource(string("host.publickey").c_str(), true).Ref()
			);
			privatekey.Load(
				FileSource(string("host.privatekey").c_str(), true).Ref()
			);
			params.Load(
				FileSource(string("key.params").c_str(), true).Ref()
			);
		}
		else
		{
			cout << "Generating new components ..." << endl;
			//Generate random key with RSA function
			params.GenerateRandomWithKeySize(rng, 1024);
			// Create key with params
			privatekey = RSA::PrivateKey(params);
			publickey = RSA::PublicKey(params);
			//Save Keys and Params
			SavingKeysAndParams(privatekey, publickey, params);
		}
	}
	else
	{
		cout << "Generating RSA Cryptography component ..." << endl;
		privatekey = RSA::PrivateKey(params);
		publickey = RSA::PublicKey(params);
		SavingKeysAndParams(privatekey, publickey, params);
	}
	/*--------------------------------------------------------------------------------------------------*/
	l();
	cout << "Starting Up Windows Socket (WSA)..." << endl;
	//Windows Socket object
	WSADATA wsa;
	SOCKET socket1 = INVALID_SOCKET, socket2 = INVALID_SOCKET; // socket1 for listen ,socket2 for client
	struct addrinfo* host = NULL;
	struct addrinfo hints;

	//StartUp Windows Socket
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		cout << "Failed starting up winsock. Error Code: " << WSAGetLastError() << endl;
		return 1;
	}

	//setup protocol and socket 
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	//int variable to check the result of connection
	int result;
	//Resolve server address
	result = getaddrinfo(NULL, to_string(promptPort()).c_str(), &hints, &host);
	cout << "Resolving address..." << endl;
	if (result != 0) {
		printf("getaddrinfo failed with error: %d\n", result);
		WSACleanup();
		return 1;
	}
	//create socket 
	socket1 = socket(host->ai_family, host->ai_socktype, host->ai_protocol);
	if (socket1 == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(host);
		WSACleanup();
		return 1;
	}

	//Setup TCP listening socket
	result = ::bind(socket1, host->ai_addr, (int)host->ai_addrlen);
	if (result == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(host);
		closesocket(socket1);
		WSACleanup();
		return 1;
	}
	//clear the host info
	freeaddrinfo(host);

	//listen for connection
	cout << "Listening for connection..." << endl;
	result = listen(socket1, SOMAXCONN);
	if (result == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(socket1);
		WSACleanup();
		return 1;
	}
	//accept client socket
	socket2 = accept(socket1 , NULL, NULL);
	if (socket2 == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(socket1);
		WSACleanup();
		return 1;
	}
	//no longer need the listening socket
	closesocket(socket1);
	cout << "Connection is ready." << endl;
	l();
	/*--------------------------------------------------------------------------------------------------*/
	char recvbuf[4096];
	int recvbuflen = 4096;

	//Receive values of key from client
	cout << "Getting Key From Client ..." << endl;
	result = recv(socket2, recvbuf, recvbuflen, 0);
	if (result == SOCKET_ERROR)
	{
		cout << "Failed receiving keys and information...\nTerminating communication..." << endl;
		closesocket(socket2);
		WSACleanup();
		return 1;
	}

	//stringstream to separate the received one
	stringstream sstream(recvbuf);
	string encrypted, decrypted;
	string publickeyC, hashValueOfKey ,client, nonce;
	//Sequence of data (hex) : Publickey(Client) , Client Name , Nonce , Hash(SHA1)
	getline(sstream, publickeyC, ':');
	getline(sstream, client, ':');
	getline(sstream, nonce, ':');
	getline(sstream, hashValueOfKey, ':');
	sstream = stringstream();
	//display
	cout << "Publickey (Client) : " << publickeyC << endl;
	StringSource getClientName(client, true, new HexDecoder(new StringSink(decrypted)));
	client = decrypted;
	decrypted = "";
	cout << "Client Name: " << client << endl;
	cout << "Nonce In Hex Form: " << nonce << endl;
	cout << "Hash Value Of publickey : " << hashValueOfKey << endl;
	l();
	//Check Publickey 
	cout << "Checking Integrity of Publickey From Client ..." << endl;
	//Decode Hash Value
	StringSource getHashValue(hashValueOfKey, true, new HexDecoder(new StringSink(decrypted)));
	hashValueOfKey = decrypted;
	decrypted = "";
	//Verify publickey
	bool valid = true;
	SHA1 shaDigest;
	try {
		StringSource verificationOfPub(hashValueOfKey + publickeyC, true, new HashVerificationFilter(shaDigest, new ArraySink((byte*)&valid, sizeof(valid))));
	}
	catch (CryptoPP::Exception& e)
	{
		cout << e.what() << endl;
	}
	if (valid)
	{
		cout << "Client PublicKey Verified." << endl;
		cout << "Sending Verified Message..." << endl;
		result = send(socket2, (hexstring((char*)"Verified")+":"+nonce+":").c_str(),(hexstring((char*)"Verified") + ":" + nonce + ":").length(), 0);
		if (result == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(socket2);
			WSACleanup();
			return 1;
		}
	}
	else
	{
		cout << "Invalid Key. Disconnect Client..." << endl;
		closesocket(socket2);
		WSACleanup();
		return 1;
	}
	l();
	//Decode publickey
	RSA::PublicKey publickeyClient;
	encrypted = "", decrypted = "";
	StringSource decodepublickey(publickeyC, true, new HexDecoder(new StringSink(encrypted)));
	StringSource ForBerDecode(encrypted, true);
	publickeyClient.BERDecode(ForBerDecode);
	encrypted = "";
	string msg;
	//Display Client Information
	cout << "Connected Client : " << client << endl;
	cout << "Nonce (Hex) :" << nonce << endl;

	bzero(recvbuf, recvbuflen);
	cout << "Waiting \'Ready\' Message From Client ..." << endl;
	result = recv(socket2, recvbuf, recvbuflen, 0);
	if (result == SOCKET_ERROR)
	{
		cout << "Fail receiving \'Ready\' Message... Closing Socket..." << endl;
		closesocket(socket2);
		WSACleanup();
		return 1;
	}
	StringSource ready(recvbuf, false, new StringSink(msg));
	ready.Pump(result);
	if (hexdecode(msg) != "Ready")
	{
		cout << "Ready message not received. Closing Socket..." << endl;
		closesocket(socket2);
		WSACleanup();
		return 1;
	}

	AutoSeededRandomPool prng;
	SecByteBlock seedkey(SEED::DEFAULT_KEYLENGTH);
	byte seediv[SEED::BLOCKSIZE];
	prng.GenerateBlock(seedkey, seedkey.size());
	prng.GenerateBlock(seediv, sizeof(seediv));
	

	cout << "Sending PublicKey To " << client << "..." << endl;
	string pbkeyhexstring;
	HexEncoder storeHEXpublickey(new StringSink(pbkeyhexstring));
	publickey.DEREncode(storeHEXpublickey);
	string hashHostPublicKey = HASH(pbkeyhexstring, shaDigest);
	
	if (sendMessage(socket2, pbkeyhexstring+":"+hashHostPublicKey+":" , (pbkeyhexstring + ":" + hashHostPublicKey + ":").length()) != 0)
	{
		return 1;
	}
	
	string encryptedSessionKey , hashvalueSessionKey, sessionkeyComponents;
	//encrypt session key with RSA PublicKey From Client
	string sessionkeystr((char*)seedkey.data());
	sessionkeystr = hexstring((char*)&sessionkeystr[0]);
	Integer sessionkey , hashSessionKey;
	sessionkey = Integer((const byte*)sessionkeystr.data(), sessionkeystr.size());
	cout << "Session Key : \n" << std::hex << sessionkey << endl;
	sessionkey = publickeyClient.ApplyFunction(sessionkey);
	cout << "Encrypted Session Key : \n" << std::hex << sessionkey << endl;
	sstream = stringstream();
	sstream << std::hex << sessionkey;
	sstream >> encryptedSessionKey;
	
	//clear stringstream
	sstream = stringstream();
	//HASH session key and encrypt it
	hashvalueSessionKey = HASH(sessionkeystr, shaDigest);
	hashvalueSessionKey = hexstring((char*)&hashvalueSessionKey[0]);
	cout << "Hash Session Key With SHA1 : " << hashvalueSessionKey << endl;
	hashSessionKey = Integer((const byte*)hashvalueSessionKey.data(), hashvalueSessionKey.size());
	hashSessionKey = publickeyClient.ApplyFunction(hashSessionKey);
	hashvalueSessionKey = "";
	sstream << std::hex << hashSessionKey;
	sstream >> hashvalueSessionKey;
	sstream = stringstream();

	//convert IV to string send together with session key
	string ivstr((char*)seediv);
	ivstr = hexstring((char*)&ivstr[0]);
	cout << "IV of Session Key : " << ivstr.c_str() << endl;
	sessionkeyComponents = encryptedSessionKey + ":" + hashvalueSessionKey + ":" + ivstr + ":";
	cout << " Sending Session Key ..." << endl;
	if (sendMessage(socket2, sessionkeyComponents, sessionkeyComponents.length()) == 1)
	{
		return 1;
	}

	CFB_Mode< SEED >::Encryption e;
	CFB_Mode< SEED >::Decryption d;
	e.SetKeyWithIV(seedkey, seedkey.size(), seediv);
	d.SetKeyWithIV(seedkey, seedkey.size(), seediv);
	
	cout << "Waiting Acknowledgement From Client ..." << endl;
	bzero(recvbuf, recvbuflen);
	result = recv(socket2, recvbuf, recvbuflen, 0);
	if (result == SOCKET_ERROR)
	{
		cout << "Fail receiving Message... Closing Socket..." << endl;
		closesocket(socket2);
		WSACleanup();
		return 1;
	}
	string temp, decryptedMessage;
	temp = recvbuf;
	temp = hexdecode(temp);
	StringSource decryptACK(temp , true, new StreamTransformationFilter(d, new StringSink(decryptedMessage)));
	
	if (decryptedMessage.compare("Acknowledge") == 0)
	{
		cout << "Acknowledgement received." << endl;
	}
	temp = "";

	//Ready Signal
	cout << "Sending Ready Signal >>> " << endl;
	encrypted = "";
	encrypted = Encrypt("Ready" , e);
	if (sendMessage(socket2, encrypted, encrypted.length()) != 0)
	{
		return 1;
	}
	l();
	cout << "Reseting Session Key with Nonce ..." << endl;
	//decode nonce and sink to byte array
	byte tempByte[4];
	StringSource decodeNonce(nonce, true, new HexDecoder(new ArraySink(tempByte, 4)));
	//replace last 4 bytes of session with nonce (discard and replace)
	bzero(&seedkey[12], 4);
	memcpy(&seedkey[12], tempByte, 4);
	//clear string variable (ensure it is empty)
	encrypted = "", decrypted = "";
	//reset key
	e.SetKeyWithIV(seedkey, 16, seediv);
	d.SetKeyWithIV(seedkey, 16, seediv);
	bool exit = false;
	l();
	cout << "Message Room" << endl;
	l();
	do
	{
		try {
			//string variable (ensure empty)
			encrypted = "", decrypted = "", msg = "";
			bzero(recvbuf, recvbuflen);

			msg = "\0";
			encrypted = "\0";
			decrypted = "\0";

			//Receiving
			cout << "Waiting message from " << client << "..." << endl;
			result = recv(socket2, recvbuf, recvbuflen, 0);
			if (result == 0)
			{
				cout << "Connection closed..." << endl;
				return 0;
			}
			encrypted = recvbuf;

			//Decryption
			decrypted = Decrypt(encrypted, d);

			//EXIT when EXIT signal received
			if (decrypted == "EXIT")
			{
				cout << "Exit signal recevied , terminating" << endl;
				return 0;
			}
			cout << "Message From " << client << " : " << decrypted;
			cout << endl;

			do {
				cout << "You (Max length : 500 characters ,'EXIT' to close * case sensitive): ";
				getline(cin, msg);
			} while (msg.length() > 500);

			exit = (msg == "EXIT");
			//Encryption
			msg = Encrypt(msg, e);
			result = sendMessage(socket2, msg, msg.length());
			if (result != 0)
			{
				cout << "Error Sending Message..." << endl;
			}
			if (exit)
			{
				cout << "Terminating Program..." << endl;
				return 0;
			}
		}
		catch (CryptoPP::Exception& e)
		{
			cout << "CryptoPP Library encounter Error , skipping ..." << endl;
			cerr << e.what() << endl;
			continue;
		}
		catch (std::exception& e)
		{
			cout << "Exception Catched, skipping ..." << endl;
			cerr << e.what() << endl;
			continue;
		}
		
	} while (1);

	closesocket(socket2);
	WSACleanup();
	cout << "Terminating Program..." << endl;

	return 0;

}

