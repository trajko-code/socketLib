#include "MySocket.h"

MySocket::MySocket(int family, int socketType, int portNum, uint32_t address)
	 : MySocket(family, socketType)
{
    this->port = portNum;
    this->address = address;
}

MySocket::MySocket(int family, int portNum, const char* address)
	: MySocket(family, socketType)
{
	this->port = portNum; 
    struct hostent *server;

    server = gethostbyname(address);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        return;
    }

    memcpy(&this->address, server->h_addr, server->h_length);
}

MySocket::MySocket(int family, int socketType, int portNum)
	: MySocket(family, socketType, portNum, INADDR_ANY)
{
}

MySocket::MySocket(int family, int socketType)
	: socketType(socketType), family(family)
{ 
}

MySocket::MySocket(int sock, struct sockaddr_in addr)
	: sockFD(sock)
{
    this->SetParamsFromStruct(addr);
}

MySocket::MySocket(int socketType)
	: MySocket(AF_INET, socketType, DEFAULT_PORT, INADDR_ANY)
{
   
}

MySocket::MySocket()
	: MySocket(AF_INET, SOCK_STREAM, DEFAULT_PORT, INADDR_ANY)
{
}

MySocket::~MySocket()
{
    close(this->sockFD);
}

bool MySocket::CreateSocket()
{
    this->sockFD = socket(this->family, this->socketType, 0);
    if(this->sockFD < 0)
    {
        PrintError("ERROR opening socket");
        return false;
    }    
    return true;
}

bool MySocket::Bind()
{
    struct sockaddr_in myStruct = this->GetAddrStruct();
    if (bind(this->sockFD, (struct sockaddr *) &myStruct, sizeof(myStruct)) < 0) 
    {
        PrintError("ERROR on binding");
        return false;
    }
    return true;        
}

bool MySocket::SetSockOption(int optName, int optValue)
{
    return SetSockOption(SOL_SOCKET, optName, optValue);
}

bool MySocket::SetSockOption(int level, int optName, int optValue)
{
    return SetSockOption(level, optName, &optValue, sizeof(optValue));
}

bool MySocket::SetSockOption(int level, int optName, const void* optValue, socklen_t optLen)
{
    if(setsockopt(this->sockFD, level, optName, optValue, optLen) == -1)
    {
        PrintError("ERROR on setting option");
        return false;
    }
    return true;
}

void MySocket::Listen(int queue)
{
    if(queue > 0 && queue < 6)
        listen(this->sockFD, queue);
    else
        listen(this->sockFD, 5);  
}

void MySocket::Listen()
{
    listen(this->sockFD, 1);
}

std::unique_ptr<MySocket> MySocket::Accept()
{
    struct sockaddr_in cliAddr;
    socklen_t clilen = sizeof(cliAddr);
    int newsockFD = accept(this->sockFD, (struct sockaddr *) &cliAddr, &clilen);
    if (newsockFD < 0)
    {
        PrintError("ERROR on accept");
        return nullptr;
    }    

    //proveriti da li je potreban neki cast za cliAddr
    return std::unique_ptr<MySocket>(new MySocket(newsockFD, cliAddr));
}

bool MySocket::Connect(int family, int portNum, uint32_t address)
{
    struct sockaddr_in servAddr;
    servAddr.sin_family = family;
    servAddr.sin_port = htons(portNum);
    servAddr.sin_addr.s_addr = address;

    if (connect(this->sockFD, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) 
    {
        PrintError("ERROR connecting"); 
        return false;
    }    
    return true;
}

bool MySocket::Connect(int family, int portNum, const char* address)
{
    struct hostent *server;

    server = gethostbyname(address);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        return false;
    }

    //struct sockaddr_in serv_addr;
    //inet_pton(family, address.c_str(), &serv_addr.sin_addr);

    uint32_t add;
    memcpy(&add, server->h_addr, server->h_length);

    return Connect(family, portNum, add);
}

int MySocket::Recieve(int sock, char *buf, size_t bufSize, int flags)
{
    bzero(buf, bufSize);
    int n = recv(sock, buf, bufSize, flags);
    if (n < 0) 
        PrintError("ERROR receiving from socket");

    return n;
}

int MySocket::Recieve(char *buf, size_t bufSize, int flags)
{
    return Recieve(this->sockFD, buf, bufSize, flags);
}

int MySocket::RecieveFrom(char *buf, size_t bufSize, int flags, MySocket& fromSock)
{
    bzero(buf, bufSize);
    socklen_t fromlen = sizeof(struct sockaddr_in);
    struct sockaddr_in from;

    int n = recvfrom(this->sockFD, buf, bufSize, flags, (struct sockaddr *)&from, &fromlen);
    if (n < 0) 
        PrintError("ERROR receiving from socket");
    else
    {
        fromSock.SetParamsFromStruct(from);
    }
    
    return n;
}


int MySocket::Read(int sock, char *buf, size_t bufSize)
{
    bzero(buf, bufSize);
    int n = read(sock, buf, bufSize);
    if (n < 0) 
        PrintError("ERROR reading from socket");

    return n;
}

int MySocket::Read(char *buf, size_t bufSize)
{
    return Read(this->sockFD, buf, bufSize);
}

int MySocket::Send(int sock, const char *buf, int bufLen, int flags)
{
    int n = send(sock, buf, bufLen, flags);
    if (n < 0) 
        PrintError("ERROR sending to socket");

    return n;
}

int MySocket::Send(const char *buf, int bufLen, int flags)
{
    return Send(this->sockFD, buf, bufLen, flags);
}

int MySocket::SendTo(const char* buf, int bufLen, int flags, const MySocket& destSock)
{
    struct sockaddr_in destAddr = destSock.GetAddrStruct();
    socklen_t destLen = sizeof(destAddr);
    int n = sendto(this->sockFD, buf, bufLen, flags, (const struct sockaddr *) &destAddr, destLen);
    if (n  < 0)
        PrintError("ERROR sending to socket");
    return n;
}

int MySocket::Write(int sock, const char *buf, int bufLen)
{
    int n = write(sock, buf, bufLen);
    if (n < 0) 
        PrintError("ERROR writing to socket");

    return n;
}

int MySocket::Write(const char *buf, int bufLen)
{
    return Write(this->sockFD, buf, bufLen);
}

void MySocket::SetParamsFromStruct(struct sockaddr_in newAddr)
{
    this->family = newAddr.sin_family;
    this->address = newAddr.sin_addr.s_addr;
    this->port = ntohs(newAddr.sin_port);
}

sockaddr_in MySocket::GetAddrStruct() const
{
    struct sockaddr_in retValue;
    bzero((char *) &retValue, sizeof(retValue));
    retValue.sin_family = this->family;
    retValue.sin_addr.s_addr = this->address;
    retValue.sin_port = htons(this->port);

    return retValue;
}

void MySocket::PrintError(const char *msg)
{
    perror(msg);
}
