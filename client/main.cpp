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
		cin.ignore(INT_MAX, '\n');

		while (cin.fail() || keyGen < 1 || keyGen >2)
		{
			cin.clear();
			cin.ignore(INT_MAX, '\n');
			cout << "1 - Using Old Existing Key \n"
				<< "2 - Generate New Key (Old key will be replaced) \n" ;
			cout << "Option : ";
			cin >> keyGen;
			cin.ignore(INT_MAX, '\n');
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
	l();
	cout << "Starting Up Windows Socket (WSA)..." << endl;
	//Windows Socket object
	WSADATA wsa;
	SOCKET socketCnt = INVALID_SOCKET;
	struct addrinfo* clientself = NULL,
		hints;
	int result;
	char recvbuf[4096];
	int recvbuflen = 4096;

	//StartUp Windows Socket
	result = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (result != 0) {
		cout << "WSAStartup failed with error: " << result << endl;
		return 1;
	}

	//setup protocol and socket 
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	//Prompt IP and Port to be connected
	string ip = promptIP();
	int portnumber = promptPort();

	cout << "Resolving address..." << endl;
	result = getaddrinfo( NULL , to_string(portnumber).c_str(), &hints, &clientself);
	if (result != 0) {
		cout << "getaddrinfo failed with error: " << result << endl;
		WSACleanup();
		return 1;
	}

		// Create a SOCKET for connecting to server
		socketCnt = socket(clientself->ai_family, clientself->ai_socktype,
			clientself->ai_protocol);
		if (socketCnt == INVALID_SOCKET) {
			cout << "socket failed with error: " << WSAGetLastError() << endl;
			WSACleanup();
			return 1;
		}

		sockaddr_in socketaddr;
		socketaddr.sin_addr.s_addr = inet_addr(ip.c_str());
		socketaddr.sin_port = htons(portnumber);
		socketaddr.sin_family = AF_INET;

		cout << "Connecting socket to address set ..." << endl;
		// Connect to server.
		result = connect(socketCnt, (SOCKADDR*)&socketaddr, sizeof(socketaddr));
		if (result == SOCKET_ERROR) {
			closesocket(socketCnt);
			socketCnt = INVALID_SOCKET;
		}

	freeaddrinfo(clientself);

	if (socketCnt == INVALID_SOCKET) {
		cout << "Unable to connect to server!" << endl;
		WSACleanup();
		return 1;
	}
	else
	{
		cout << "Connection is ready..." << endl;
	}

	l();
	getpeerinfo(socketCnt);
	l();
	string TransferTemp = "";

	//Prompt Client name
	string name;
	cout << "Enter your name as ID (no space): ";
	cin >> name;
	cin.ignore(INT_MAX, '\n');

	//Generate Nonce
	cout << "Generating nonce ... " << endl;
	byte nonce[4];
	rng.GenerateBlock(nonce, 4);
	//Encode the key
	cout << "Encoding RSA PublicKey..." << endl;
	string pbkeyhexstring;
	HexEncoder storeHEXpublickey(new StringSink(pbkeyhexstring));
	publickey.DEREncode(storeHEXpublickey);
	SHA1 sha1;
	//Encode Nonce
	cout << "Encoding Nonce ..." << endl;
	string noncestr;
	ArraySource nonceToHex(nonce, 4, true, new HexEncoder(new StringSink(noncestr)));
	//SHA1 Hash PublicKey
	cout << "SHA hashing Encoded PublicKey" << endl;
	string hashvalue = HASH(pbkeyhexstring, sha1);

	//Display
	cout << "Encoded Publickey : " << pbkeyhexstring << endl;
	cout << "Hash value : " << hashvalue << endl;
	cout << "Nonce : " << noncestr << endl;

	//Concatenate key , hash , nonce
	TransferTemp = pbkeyhexstring + ":" + hexstring((char*)&name[0]) + ":" + noncestr + ":" + hashvalue + ":";

	//send the product to server
	l(); cout << "Sending To Server ..." << endl;
	result = sendMessage(socketCnt, TransferTemp, (int)strlen(TransferTemp.c_str()));
	if (result != 0)
		return 0;
	bzero(recvbuf, recvbuflen);
	cout << "Waiting Server to Verify ..." << endl;
	result = recv(socketCnt, recvbuf, recvbuflen, 0);
	if (result == SOCKET_ERROR)
	{
		cout << "Failed Receiving Verification Data... Closing Socket..." << endl;
		closesocket(socketCnt);
		WSACleanup();
		return 1;
	}
	stringstream sstream;
	string msg;
	sstream.str(recvbuf);
	getline(sstream, msg, ':');
	if (hexdecode(msg) == "Verified")
	{
		msg = "";
		getline(sstream, msg, ':');
		cout << "Checking Nonce ..." << endl;
		if (msg == noncestr)
		{
			cout << "Message \"Verified\" received.\nNonces are matched.\nSending ready signal ..." << endl;
			msg = "";
			msg = hexstring((char*)"Ready");
			if (sendMessage(socketCnt, msg, msg.length()) != 0)
			{
				return 1;
			}
			msg = "";
		}
		sstream = stringstream();
	}
	else
	{
		cout << "Failure On Verification... Closing Socket..." << endl;
		closesocket(socketCnt);
		WSACleanup();
		return 1;
	}
	l();

	bzero(recvbuf, recvbuflen);
	cout << "Getting PublicKey From Server ..." << endl;
	result = recv(socketCnt, recvbuf, recvbuflen, 0);
	if (result == SOCKET_ERROR)
	{
		cout << "Failed receiving keys...\nTerminating communication..." << endl;
		closesocket(socketCnt);
		WSACleanup();
		return 1;
	}
	sstream.str(recvbuf);
	string publickeyH, hashValueOfServerKey , decoded;
	getline(sstream, publickeyH, ':');
	getline(sstream, hashValueOfServerKey, ':');
	sstream = stringstream();
	cout << "PublicKey Value Received : " << publickeyH << endl;
	cout << "Hash Value of Server PublicKey : " << hashValueOfServerKey << endl;
	l();
	//Check Publickey 
	cout << "Checking Integrity of Publickey From Server ..." << endl;
	//Decode Hash Value
	StringSource getHashValue(hashValueOfServerKey, true, new HexDecoder(new StringSink(decoded)));
	hashValueOfServerKey = decoded;
	decoded = "";
	bool valid;
	StringSource verificationOfPub(hashValueOfServerKey + publickeyH , true, new HashVerificationFilter(sha1, new ArraySink((byte*)&valid, sizeof(valid))));
	if (valid)
	{
		cout << "PublicKey From Server Verified..." << endl;
	}
	else
	{
		cout << "Failed verifying integrity of PublicKey From Server..." << endl;
		closesocket(socketCnt);
		WSACleanup();
		return 1;
	}
	l();

	cout << "Getting Session Key From Server ..." << endl;
	//Receive SEED session key
	result = recv(socketCnt, recvbuf, recvbuflen, 0);
	if (result == SOCKET_ERROR)
	{
		cout << "Failed receiving ...\nTerminating communication..." << endl;
		closesocket(socketCnt);
		WSACleanup();
		return 1;
	}
	cout << "Processing Package Received ..." << endl;
	string sessionkey, hashsessionkey , DecryptedSessionKey , DecryptedHash , iv;
	sstream.str(recvbuf);
	getline(sstream, sessionkey, ':');
	getline(sstream, hashsessionkey, ':');
	getline(sstream, iv, ':');
	sstream = stringstream();

	cout << "Decrypting Session Key ..." << endl;
	l();
	Integer skEncrypted;
	//decrypt session key
	try {
		sessionkey= hexdecode(sessionkey);
		skEncrypted = Integer((const byte*)sessionkey.data(), sessionkey.size());
		
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
	
	Integer skDecrypted = privatekey.CalculateInverse(rng, skEncrypted);
	
	size_t req = skDecrypted.MinEncodedSize();
	DecryptedSessionKey.resize(req);
	skDecrypted.Encode((byte*)DecryptedSessionKey.data(), DecryptedSessionKey.size());
	DecryptedSessionKey = hexdecode(DecryptedSessionKey);
	SecByteBlock FinalSessionKey((const byte*)DecryptedSessionKey.data(), SEED::DEFAULT_KEYLENGTH); // Create Byte Block keeping the session key
	cout << "Decrypted session key: " << hex << skDecrypted << endl;

	
	//decrypt hash value of session key
	hashsessionkey = hexdecode(hashsessionkey);
	Integer hskEncrypted = Integer((const byte*)hashsessionkey.data(), hashsessionkey.size());
	Integer hskDecrypted = privatekey.CalculateInverse(rng, hskEncrypted);
	req = hskDecrypted.MinEncodedSize();
	DecryptedHash.resize(req);
	hskDecrypted.Encode((byte*)DecryptedHash.data(), DecryptedHash.size());
	cout << "Decrypted session key hash: " << DecryptedHash<< endl;

	cout << "Verifying integrity of session key ..." << endl;
	try
	{
		valid = (hexdecode(DecryptedHash).compare(HASH(hexstring((char*)&DecryptedSessionKey[0]),sha1)) == 0);
		if (valid)
		{
			cout << "Session Key verified." << endl;
		}
		else
		{
			cout << "Failed verifying session key... " << endl;
			return 1;
		}
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}
	cout << "IV of Session Key : " << iv.c_str() << endl;
	iv = hexdecode(iv);
	l();
	//Setup the keys
	cout << "Setting up the encryption and decryption functions..." << endl;
	CFB_Mode< SEED >::Encryption e;
	CFB_Mode< SEED >::Decryption d;
	string outputTemp = "";
	try
	{
		
		e.SetKeyWithIV(FinalSessionKey, FinalSessionKey.size() , (byte*)iv.c_str());
		d.SetKeyWithIV(FinalSessionKey, FinalSessionKey.size() , (byte*)iv.c_str());

		msg = "Acknowledge";
		// StreamTransformationFilter
		StringSource ack(msg, true,
			new StreamTransformationFilter(e,
				(new StringSink(outputTemp))
			)
		);
		outputTemp = hexstring((char*)&outputTemp[0]);
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		
	}
	int count = 0 ; 
	cout << "Sending Acknowledgement To Server ... " << endl;
	count = sendMessage(socketCnt, outputTemp, outputTemp.length());
	if (count != 0)
	{
		return 1;
	}

	bzero(recvbuf, recvbuflen);
	result = recv(socketCnt, recvbuf, recvbuflen, 0);
	if (result == SOCKET_ERROR)
	{
		cout << "Failed receiving ready signal...\nTerminating communication..." << endl;
		closesocket(socketCnt);
		WSACleanup();
		return 1;
	}
	string temp , decryptedMessage;
	temp = recvbuf;
	
	decryptedMessage = Decrypt(temp, d);
	if (decryptedMessage.compare("Ready") == 0)
	{
		cout << "Ready Signal Received..." << endl;
	}
	else
	{
		cout << "Time out. Ready Signal Not Received. \nClosing Socket..." << endl;
		return 0;
	}

	cout << "Reseting Session Key with Nonce ..." << endl;
	//replace last 4 bytes of session with nonce (discard and combine)
	bzero(&FinalSessionKey[12], 4);
	memcpy(&FinalSessionKey[12], nonce , 4);

	e.SetKeyWithIV(FinalSessionKey, 16, (byte*)iv.c_str());
	d.SetKeyWithIV(FinalSessionKey, 16, (byte*)iv.c_str());

	//Decode server publickey
	RSA::PublicKey publickeyServer;
	string encrypted = "", decrypted = "";
	StringSource decodepublickey(publickeyH, true, new HexDecoder(new StringSink(encrypted)));
	StringSource ForBerDecode(encrypted, true);
	publickeyServer.BERDecode(ForBerDecode);
	l();
	cout << "Message Room" << endl;
	l();
	bool exit = false;
	do
	{
		try {
			//string variable (ensure empty)
			encrypted = "", decrypted = "", msg = "";
			bzero(recvbuf, recvbuflen);

			do {
				cout << "You (Max length : 500 characters ,'EXIT' to close * case sensitive): ";
				getline(cin, msg);
			} while (msg.length() > 500);
			
			
			//Encryption
			exit = (msg == "EXIT");
			msg = Encrypt(msg, e);
			result = sendMessage(socketCnt, msg, msg.length());
			if (result != 0)
			{
				cout << "Error Sending Message..." << endl;
			}
			if (exit)
			{
				cout << "Terminating Program..." << endl;
				return 0;
			}

			msg = "\0";
			encrypted = "\0";
			decrypted = "\0";

			//Receiving
			cout << "Waiting message from server..." << endl;
			result = recv(socketCnt, recvbuf, recvbuflen, 0);
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
			cout << "Message From Server: " << decrypted;
			cout << endl;
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

	closesocket(socketCnt);
	WSACleanup();
	cout << "Terminating Program..." << endl;

	return 0;
}

