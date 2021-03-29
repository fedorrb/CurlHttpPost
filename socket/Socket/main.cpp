//	Федорчук Р.Б.
//--------------------------------------
// Программа для обмена сообщениями через сокет
// формат вхідних повідомлень JSON
//--------------------------------------
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <string>
#include <exception>
#include <stdio.h>

//#include <cstdlib>

#include <normalize.h>
#include "klovr.h"
#include "xstay.h"
#include "interface.h"
#include "common.h"
#include "mat.hpp"
#include "singleton.h"
#include <stdlib.h>
#include "serveraddr.h"
#include "busyindc.h"//BUSY_FORM
#include "moduls_check.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <winbase.h>
#define LIBCURL_VERSION_NUM 0x071303
#define CURL_STATICLIB
#include <curl/curl.h>
#pragma comment(lib, "libcurl.lib" )
#pragma comment(lib, "ws2_32.lib" )
#pragma comment(lib, "Wldap32.lib" )

using namespace std;
using std::string;
using std::vector;

vector<string> messageToSend;
vector<string> receivedLines;
vector<string> errorMessage;
StayEventProc BOSBusyForm; //BUSY_FORM
StayEventProc BOSWSetAddr;
void SaveJsonToFile (const char *out_filename, int code, vector<string> & receivedLines);
int SaveLogFile (vector<string> & messageToSend, int direction);
const int MAXMESSAGE = 131072; //#define DEFAULT_BUFLEN 1024 in socketcl.h
const unsigned long MAXLOGFILESIZE = 20000000; //20Mb
void replaceAll(std::string& str, const std::string& from, const std::string& to);
int CUrlHttpClient(string ip, string port, vector<string>& messageToSend, vector<string>& receivedMessage);
bool LoadJsonFromFile(const char* in_filename, vector<string>& messageToSend);
void GetSystemInfo();
void GetAddress(string& srvrIP, string& srvrPort);

USETOOLS;USESHELL;USETECH;

ASOPDMAIN("Messaging with the server");

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int main(int argc, char** argv)
{
	int result = 1;

	INITTOOLS(); INITSHELL(); INITTECH();
	Singleton& glb = Singleton::getInstance(); 	//creating an instance of a class of global variables
	StackReset();
	SetDateDelim('.');
	Initiate();
	char sokPath[80];
	glb.debug = false;
	if (!StartProcSet(&glb.insCode, NULL, glb.insFio, NULL))
	{
		glb.rayon = 3225;
		glb.uzel = 3225;
		glb.debug = true;
	}
	else
	{
		glb.rayon = fGetTech("район");
		glb.uzel = fGetTech("узел");
		if (fGetTech("DEBUG"))
			glb.debug = true;
	}
	GetSystemInfo();
	if (glb.debug) {
		FullPath(sokPath, "SOK:");
		glb.debugPath = sokPath;
	}
	else {
		glb.debugPath = "";
	}

	if(argc == 4) {
		glb.pathAdmin = argv[0];
		glb.fileNameIn = argv[1]; //file with incoming message
		glb.fileNameOut = argv[2]; //file for outgoing message
		glb.reqCode = argv[3]; //exchange code
		glb.vidpov = 1;
		Display (WndBusy, BOSBusyForm);//BUSY_FORM
		result = glb.vidpov;
	}
	else {
		glb.reqCode = "999";
		glb.pathAdmin = argv[0];
		Display (WndSetAddr, BOSWSetAddr);
	}
	if(B_SvrAdr->bs)
		Close(B_SvrAdr);
	Terminate();
	TERMTOOLS();TERMSHELL();TERMTECH();
	return result; 
}

//returns the contents of the input file to a vector
bool LoadJsonFromFile(const char* in_filename, vector<string>& messageToSend) {
	Singleton& glb = Singleton::getInstance();
	bool result = false;
	char buf[MAXMESSAGE];
	char bufNew[MAXMESSAGE];
	memset(bufNew, 0, MAXMESSAGE);
	messageToSend.clear();
	StayFile fJsonIn;
	fJsonIn = FOpen(in_filename, RD | ANRD);
	if (fJsonIn) {
		FSeek(fJsonIn, 0);
		while (FReadText(fJsonIn, buf, MAXMESSAGE) > 0) {
			messageToSend.push_back(buf);
		}
		FClose(fJsonIn);
		result = true;
	}
	return result;
}

void SaveJsonToFile (const char *out_filename, int code, vector<string> & receivedLines) {
	char ansCode[4];
	memset(ansCode, 0, sizeof(ansCode));
	StrForm(ansCode, 3, "-1|");//error
	StayFile fJsonOut;
    fJsonOut=FCreate(out_filename, RDWR);
	if(fJsonOut) {
		if(code < 0)
			FWrite(fJsonOut, ansCode, (int)strlen(ansCode));
		for(std::vector<string>::iterator it = receivedLines.begin(); it != receivedLines.end(); ++it) {
			FWrite(fJsonOut, (*it).c_str(), (int) strlen((*it).c_str()));
		}
		FClose(fJsonOut);
	}
}

int SaveLogFile (vector<string> & messageToSend, int direction) {
	int result = 0;
	Singleton &glb = Singleton::getInstance();
	char buf[MAXMESSAGE];
	char buf_inout[4];
	char name_log_file[256];
	if(direction)
		StrCpy(buf_inout, "in");
	else
		StrCpy(buf_inout, "out");
	StayDate dtNow = GetSysDate();
	StayTime tmNow = GetSysTime();

	vector<string> splitLines;
	splitLines.clear();
	Normalize *Norm = new Normalize();
	for(std::vector<string>::iterator it = messageToSend.begin(); it != messageToSend.end(); ++it) {
		Norm->SplitStringLine((*it), splitLines);
	}
	Norm->ModifyLengthCol(splitLines);
	delete Norm;
	int size_v = static_cast<int>(splitLines.size());

	unsigned long fileSize = 0;

	StrForm(buf, MAXMESSAGE, "\r\n%10v %5t %3s code:%s", dtNow, tmNow, buf_inout, glb.reqCode);
	StayFile logFile;
	int len = StrLen(buf);
	StrForm(name_log_file, 256, "SOK:socket%u.log", glb.insCode);
	try {
		if(FFind(name_log_file, NULL)) {
			logFile = FOpen(name_log_file, RDWR | ANRD);
		} else {
			logFile = FCreate(name_log_file, RDWR | ANRD);
		}
	} catch (...){
		if(logFile)
			FClose(logFile);
		result = 1;
	}
	if(result)
		return result;
	//if log file bigger than MAXLOGFILESIZE
	fileSize = FSize(logFile);
	if(logFile && fileSize > MAXLOGFILESIZE) {
		FClose(logFile);
		char name2[L_tmpnam];
		if(std::tmpnam(name2)) {
			name2[0] = ':';
			std::string name1 = name2;
			std::string nameFull = "SOK" + name1 + "log";
			FCopy(name_log_file, nameFull.c_str());
			logFile = FCreate(name_log_file, RDWR | ANRD);
	    }
	}
	if(logFile) {
		FSeek(logFile,FSize(logFile));
		FWrite(logFile, buf, len);
		int i = 0;
		while(i < size_v) {
			FWrite(logFile, splitLines[i].c_str(), (int) strlen(splitLines[i].c_str()));
			i++;
		}
		FFlush(logFile);
		FClose(logFile);
	}
	return result;
}

//BUSY_FORM
int STAYPROC BOSBusyForm( StayEvent s, StayEvent id )
{
	char jsonOut[MAXMESSAGE];
	jsonOut[0] = '\0';
	string srvrIP = "10.0.8.92";
	string srvrPort = "1871";
	Singleton &glb = Singleton::getInstance();
	char errorMsg[100];
	errorMsg[0] = '\0';
	int fieldlen = 0;
	short ptkCode = 0;
	unsigned short pcPort = 1861;

	switch( s )
	{
	case _BeforeWindow:
		if (!B_SvrAdr->bs)
			OpenCreate(B_SvrAdr, RDWR | ANRDWR);
		GetAddress(srvrIP, srvrPort);
		if (B_SvrAdr->bs)
			Close(B_SvrAdr);
		if (LoadJsonFromFile(glb.fileNameIn.c_str(), messageToSend)) {
			if (CUrlHttpClient(srvrIP, srvrPort, messageToSend, receivedLines)) {
				//error
				SaveJsonToFile(glb.fileNameOut.c_str(), -1, receivedLines);
				SaveLogFile(messageToSend, 0);
				SaveLogFile(receivedLines, 1);
			}
			else {
				//ok
				glb.vidpov = 0;
				SaveJsonToFile(glb.fileNameOut.c_str(), 0, receivedLines);
				SaveLogFile(messageToSend, 0);
				SaveLogFile(receivedLines, 1);
			}
		}
		else {
			string err = "Input File Error";
			receivedLines.clear();
			receivedLines.push_back(err);
			SaveJsonToFile(glb.fileNameOut.c_str(), -1, receivedLines);
			SaveLogFile(receivedLines, 0);
		}

		Exit(_Ok);
		break;
	}
	return 0;
}

int STAYPROC BOSWSetAddr( StayEvent s, StayEvent id )
{
	Singleton &glb = Singleton::getInstance();
	string srvrIP = "10.0.8.92";
	string srvrPort = "1871";
	char buf[MAXMESSAGE];
	unsigned short srvrDL = 4; 
	unsigned short srvrAT = 10;
	char errorMsg[100];
	memset(errorMsg, 0, sizeof(errorMsg));	
	char buf1[64];
	memset(buf1, 0, sizeof(buf1));
	StrForm(buf1,64,"[{\"TEST\":\"TEST\"}]");
	string strJsonIn = buf1;
	string strJsonOk = "{\"TEST\":\"OK\"}";
	vector<string> textToSend;
	string errorStr = "";
	int loc = 0;

	switch( s )
	{
	case _BeforeWindow:
		if (!B_SvrAdr->bs)
			OpenCreate(B_SvrAdr, RDWR | ANRDWR);
		GetAddress(srvrIP, srvrPort);
		ShowWnd( NULL );
		break;
	case _Enter:
	case BUT1:
		Modify(B_SvrAdr);
		if(B_SvrAdr->bs)
			Close(B_SvrAdr);
		StrForm(buf, MAXMESSAGE, "%s %s %D %D", J_SRVIP, J_SRVPORT, _J_SRVDL, _J_SRVAT);
		errorMessage.clear();
		errorMessage.push_back(buf);
		SaveLogFile(errorMessage, 0);
		Exit(_Ok);
		break;
	case BUT2:
		Modify(B_SvrAdr);
		receivedLines.clear();
		if(Size(B_SvrAdr)) {
			textToSend.clear();
			receivedLines.clear();
			SetBegin(B_SvrAdr);
			GetNext(B_SvrAdr);
			srvrIP = J_SRVIP;
			srvrPort = J_SRVPORT;
			textToSend.push_back(strJsonIn);
			if (CUrlHttpClient(srvrIP, srvrPort, textToSend, receivedLines)) {
				//if(receivedLines.size())
					//errorStr = receivedLines[0];
				receivedLines.push_back(".    IP = " + srvrIP + ", PORT = " + srvrPort);
				SaveLogFile(receivedLines, 1);//error
			}
			else {
				std::transform(receivedLines[0].begin(), receivedLines[0].end(), receivedLines[0].begin(), ::toupper);
				loc = receivedLines[0].find(strJsonOk);
				if (loc != string::npos)
					MsgBox("Тест ОК", "Тест ОК");
				else {
					//if(receivedLines.size())
						//errorStr = receivedLines[0];
					MsgBox("Помилка", errorStr.c_str());
				}
				receivedLines.push_back(".    IP = " + srvrIP + ", PORT = " + srvrPort);
				SaveLogFile(receivedLines, 1);//ok
			}
		}
		else {
			StrForm(errorMsg, 100, "Не введено ір-адресу сервера!");
			MsgBox("Помилка", errorMsg);
		}
		break;
	}
	return 0;
}

//https://stackoverflow.com/questions/3418231/replace-part-of-a-string-with-another-string
void replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if(from.empty())
        return;
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

int CUrlHttpClient(string ip, string port, vector<string>& messageToSend, vector<string>& receivedMessage)
{
	Singleton &glb = Singleton::getInstance();
	receivedMessage.clear();
	CURL* curl;
	CURLcode res;
	int intPort = 1871;
	try {
		intPort = std::atoi(port.c_str());
	} catch (...) {
		intPort = 1871;
	}
	string target = ip + "/api/asopd/v2/r/" + glb.reqCode;
	// In windows, this will init the winsock stuff 
	curl_global_init(CURL_GLOBAL_ALL);
	std::string readBuffer;
	std::string jsonstr = messageToSend[0];
	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, target.c_str());
		curl_easy_setopt(curl, CURLOPT_PORT, intPort);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonstr.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		MsgBox("",readBuffer.c_str());
		receivedMessage.push_back(readBuffer);
	}
	curl_global_cleanup();
	return 0;
}

void GetSystemInfo() {
	Singleton& glb = Singleton::getInstance();
	//md5
	char pathPrototype[256];
	glb.md5 = "not found prototype";
	if (FFind("ASOPD:prototype.ini")) {
		FullPath(pathPrototype, "ASOPD:prototype.ini");
		glb.md5 = GetMD5(pathPrototype);
	}
	// Get the Windows version.
	DWORD dwVersion = 0;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuild = 0;
	dwVersion = GetVersion();
	glb.dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	glb.dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));
	// Get the build number.
	if (dwVersion < 0x80000000)
		dwBuild = (DWORD)(HIWORD(dwVersion));
	//SYSTEM_INFO structure
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);
	glb.dwNumberOfProcessors = siSysInfo.dwNumberOfProcessors;
	glb.dwPageSize = siSysInfo.dwPageSize;
	//Screen
	glb.screenX = GetSystemMetrics(SM_CXSCREEN);
	glb.screenY = GetSystemMetrics(SM_CYSCREEN);
	int maxx = 0;
	int maxy = 0;
	DEVMODE dm = { 0 };
	dm.dmSize = sizeof(dm);
	for (int iModeNum = 0; EnumDisplaySettings(NULL, iModeNum, &dm) != 0; iModeNum++) { //iModeNum = ENUM_CURRENT_SETTINGS
		if (dm.dmPelsWidth > maxx) {
			glb.screenMaxX = dm.dmPelsWidth;
			glb.screenMaxY = dm.dmPelsHeight;
		}
	}
	//RAM
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	glb.dwRamSize = statex.ullTotalPhys / (1024*1024);
}

void GetAddress(string& srvrIP, string& srvrPort) {
	Singleton& glb = Singleton::getInstance();
	if (Size(B_SvrAdr)) {
		SetBegin(B_SvrAdr);
		GetNext(B_SvrAdr);
		srvrIP = J_SRVIP;
		srvrPort = J_SRVPORT;
	}
	else {
		StrForm(J_SRVIP, 15, srvrIP.c_str());
		StrForm(J_SRVPORT, 5, srvrPort.c_str());
		J_SRVDL = 4;
		J_SRVAT = 10;
		J_SRVType = 25;
		Put(B_SvrAdr);
	}
}