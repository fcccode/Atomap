#pragma once

/*
*
* ATOMAP by Louka
* https://github.com/LoukaMB
*
* Single-header manual mapping injection library
* C++11 or anything newer should work with this
*
*/

#ifndef H_ATOMAP
#define H_ATOMAP

#ifndef _WIN32
	#error Atomap is a Windows-only library
#endif

/*	Setting this allows you to define the third argument (lpReserved) passed to the DLL's entrypoint.
You can use this to, for example, assure that only your injector can be used to inject
a certain DLL into a process (if the third argument is different, then you know that
a different injector was used) */
#define ATOMAP_RESERVED_DATA 0x00000000

#include <Windows.h>

class Atomap
{
private:
	typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
	typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
	typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);
	struct InjectInformation
	{
		PVOID ProcessBase;
		PIMAGE_NT_HEADERS NtHeaders;
		PIMAGE_BASE_RELOCATION BaseRelocation;
		PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
		pLoadLibraryA fnLoadLibraryA;
		pGetProcAddress fnGetProcAddress;
	};

	static DWORD WINAPI ExportedCodeCave(InjectInformation* InjectInfo)
	{
		HMODULE hModule;
		PIMAGE_BASE_RELOCATION pIBR;
		PIMAGE_IMPORT_DESCRIPTOR pIID;
		PIMAGE_IMPORT_BY_NAME pIBN;
		PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;
		PDLL_MAIN EntryPoint;
		DWORD Delta;

		pIBR = InjectInfo->BaseRelocation;
		Delta = (DWORD)((LPBYTE)InjectInfo->ProcessBase - InjectInfo->NtHeaders->OptionalHeader.ImageBase);

#pragma region Image Relocation
		while (pIBR->VirtualAddress)
		{
			if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				DWORD count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				PDWORD ptr = NULL;
				PWORD list = (PWORD)(pIBR + 1);

				for (int i = 0; i < count; i++)
				{
					if (list[i])
					{
						ptr = (PDWORD)((LPBYTE)InjectInfo->ProcessBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
						*ptr += Delta;
					}
				}
			}

			pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
		}
#pragma endregion

#pragma region DLL Import Resolve
		DWORD Function;
		pIID = InjectInfo->ImportDirectory;

		while (pIID->Characteristics)
		{
			OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)InjectInfo->ProcessBase + pIID->OriginalFirstThunk);
			FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)InjectInfo->ProcessBase + pIID->FirstThunk);
			hModule = InjectInfo->fnLoadLibraryA((LPCSTR)InjectInfo->ProcessBase + pIID->Name);
			if (!hModule)
				return FALSE;
			while (OrigFirstThunk->u1.AddressOfData)
			{
				if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					Function = (DWORD)InjectInfo->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
					if (!Function)
						return FALSE;
					FirstThunk->u1.Function = Function;
				}
				else
				{
					pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)InjectInfo->ProcessBase + OrigFirstThunk->u1.AddressOfData);
					Function = (DWORD)InjectInfo->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
					if (!Function)
						return FALSE;
					FirstThunk->u1.Function = Function;
				}
				OrigFirstThunk++;
				FirstThunk++;
			}
			pIID++;
		}
#pragma endregion
		if (InjectInfo->NtHeaders->OptionalHeader.AddressOfEntryPoint)
		{
			EntryPoint = (PDLL_MAIN)((LPBYTE)InjectInfo->ProcessBase + InjectInfo->NtHeaders->OptionalHeader.AddressOfEntryPoint);
			return EntryPoint((HMODULE)InjectInfo->ProcessBase, DLL_PROCESS_ATTACH, ATOMAP_RESERVED_DATA);
		}

		return TRUE;
	};

	static void __declspec(naked) ExportedCodeCaveEnd()
	{

	}

public:
	static DWORD Inject(LPCSTR Path, DWORD ProcessId)
	{
		InjectInformation InjInfo;
		PIMAGE_DOS_HEADER pIDH;
		PIMAGE_NT_HEADERS pINH;
		PIMAGE_SECTION_HEADER pISH;
		DWORD FileSize, BytesRead;
		HANDLE hProcess, hThread, hFile, hToken;
		PVOID FileBuffer, Image, Loader, InjectInfo;

#pragma region Reading binary
		hFile = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		FileSize = GetFileSize(hFile, NULL);
		FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		ReadFile(hFile, FileBuffer, FileSize, &BytesRead, NULL);
		CloseHandle(hFile);
#pragma endregion

#pragma region Allocating and invoking binary
		pIDH = (PIMAGE_DOS_HEADER)(FileBuffer);
		pINH = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pIDH->e_lfanew);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
		Image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(hProcess, Image, FileBuffer, pINH->OptionalHeader.SizeOfHeaders, NULL);
		pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);
		for (DWORD i = 0; i<pINH->FileHeader.NumberOfSections; i++)
			WriteProcessMemory(hProcess, (PVOID)((LPBYTE)Image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)FileBuffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
		Loader = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		InjectInfo = VirtualAllocEx(hProcess, NULL, sizeof(InjectInformation), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		InjInfo.ProcessBase = Image;
		InjInfo.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)Image + pIDH->e_lfanew);
		InjInfo.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)Image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		InjInfo.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)Image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		InjInfo.fnLoadLibraryA = LoadLibraryA;
		InjInfo.fnGetProcAddress = GetProcAddress;
		WriteProcessMemory(hProcess, InjectInfo, &InjInfo, sizeof(InjectInformation), NULL);
		WriteProcessMemory(hProcess, Loader, ExportedCodeCave, (DWORD)ExportedCodeCaveEnd - (DWORD)ExportedCodeCave, NULL);
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(Loader), InjectInfo, 0, NULL);
		return TRUE;
#pragma endregion
	};
};

#endif