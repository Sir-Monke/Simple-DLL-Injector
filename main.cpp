#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <string>
#include <iostream>
#include <random>

using namespace std;

class Injector {
public:
    bool InjectDll() {
        uintptr_t ProcId = GetProcId();
        if (ProcId != 0) {
            const char* DLLPath = GetDLLPath();
            HANDLE OpenProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, ProcId);
            if (OpenProc != NULL) {
                void* lpBaseAddress = VirtualAllocEx(OpenProc, NULL, strlen(DLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (lpBaseAddress != NULL) {
                    if (WriteProcessMemory(OpenProc, lpBaseAddress, DLLPath, strlen(DLLPath) + 1, NULL)) {
                        HMODULE kernel32base = GetModuleHandle(L"kernel32.dll");
                        FARPROC pLoadLibraryA = GetProcAddress(kernel32base, "LoadLibraryA");
                        HANDLE thread = CreateRemoteThread(OpenProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, lpBaseAddress, 0, NULL);
                        if (thread != NULL) {
                            WaitForSingleObject(thread, INFINITE);
                            CloseHandle(thread);
                            std::cout << DLLPath << endl;
                            std::cout << ProcId << endl;
                            std::cout << "Injected" << endl;
                            return 1;
                        }
                    }
                    VirtualFreeEx(OpenProc, lpBaseAddress, 0, MEM_RELEASE);
                }
                CloseHandle(OpenProc);
            }
        } else {
            std::cout << "Cant Find Game" << endl;
            return 0;
        }
    }

    const char* GetDLLPath() {
        std::string path = "dllFolderPathHere";
        WIN32_FIND_DATAA findFileData;
        HANDLE hFind;

        std::string searchPath = path + "\\\\*";

        hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::string fileName = findFileData.cFileName;
                    if (fileName.substr(fileName.find_last_of(".") + 1) == "dll") {
                        std::string fullPath = path + "\\\\" + fileName;
                        std::mt19937 rng(std::time(nullptr));
                        std::uniform_int_distribution<int> dist(10000, 99999);
                        std::string randomName = "NewDLL_" + std::to_string(dist(rng)) + ".dll";
                        std::string copiedPath = path + "\\\\" + randomName;
                        if (CopyFileA(fullPath.c_str(), copiedPath.c_str(), FALSE)) {
                            size_t length = copiedPath.length() + 1;
                            char* result = new char[length];
                            strcpy_s(result, length, copiedPath.c_str());
                            FindClose(hFind);
                            return result;
                        }
                        else {
                            std::cout << "Failed to copy DLL." << std::endl;
                        }
                    }
                }
            } while (FindNextFileA(hFind, &findFileData) != 0);
            FindClose(hFind);
        }
        return nullptr;
    }

    uintptr_t GetProcId() {
        const wchar_t* ProcName = L"procNameHere";
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        uintptr_t ProcID = 0;

        if (hProcessSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 ProcEntry;
            ProcEntry.dwSize = sizeof(ProcEntry);
            if (Process32First(hProcessSnap, &ProcEntry)) {
                do {
                    if (_wcsicmp(ProcEntry.szExeFile, ProcName) == 0) {
                        ProcID = ProcEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hProcessSnap, &ProcEntry));
            }
        }
        CloseHandle(hProcessSnap);
        return ProcID;
    }
};

int main() {
    Injector WinInjec;
    int Uinject;

    while (1) {
        cin >> Uinject;
        if (Uinject == 1) {
            WinInjec.InjectDll();
        } else {
            system("CLS");
        }
    }
    return 0;
}
