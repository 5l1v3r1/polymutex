/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#define UNICODE
  
#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

LPVOID xmalloc (SIZE_T dwSize);
LPVOID xrealloc (LPVOID lpMem, SIZE_T dwSize);
VOID xfree (LPVOID lpMem);

#define STATUS_INFO_LEN_MISMATCH 0xC0000004

#if defined (__GNUC__)
typedef unsigned long NTSTATUS;
#endif

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING; 
 
typedef struct _OBJECT_NAME_INFORMATION { 
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
 
typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolSession = 32,
    PagedPoolSession,
    NonPagedPoolMustSucceedSession,
    DontUseThisTypeSession,
    NonPagedPoolCacheAlignedSession,
    PagedPoolCacheAlignedSession,
    NonPagedPoolCacheAlignedMustSSession
} POOL_TYPE;
 
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16,
} SYSTEM_INFORMATION_CLASS;

typedef struct  _SYSTEM_HANDLE {
    ULONG       ProcessId;
    UCHAR       ObjectTypeNumber;
    UCHAR       Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE,  *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
 
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllTypesInformation,
    ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;
 
typedef struct  _OBJECT_BASIC_INFORMATION {
    ULONG           Attributes;
    ACCESS_MASK     GrantedAccess;
    ULONG           HandleCount;
    ULONG           PointerCount;
    ULONG           PagedPoolUsage;
    ULONG           NonPagedPoolUsage;
    ULONG           Reserved[3];
    ULONG           NameInformationLength;
    ULONG           TypeInformationLength;
    ULONG           SecurityDescriptorLength;
    LARGE_INTEGER   CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;
 
typedef struct  _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING  Name;
    ULONG           ObjectCount;
    ULONG           HandleCount;
    ULONG           Reserved1   [   4];
    ULONG           PeakObjectCount;
    ULONG           PeakHandleCount;
    ULONG           Reserved2   [   4];
    ULONG           InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG           ValidAccess;
    UCHAR           Unknown;
    BOOLEAN         MaintainHandleDatabase;
    POOL_TYPE       PoolType;
    ULONG           PagedPoolUsage;
    ULONG           NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
 
typedef NTSTATUS (WINAPI *pNtQuerySystemInformation) (
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength);
    
typedef NTSTATUS (WINAPI *pNtDuplicateObject) (
    HANDLE      SourceProcessHandle,
    HANDLE      SourceHandle,
    HANDLE      TargetProcessHandle,
    PHANDLE     TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Options);
    
typedef NTSTATUS (WINAPI *pNtQueryObject) (
    HANDLE                   Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID                    ObjectInformation,
    ULONG                    ObjectInformationLength,
    PULONG                   ReturnLength);
 
typedef NTSTATUS (WINAPI *pNtClose) (
    HANDLE Handle);
 
typedef struct _HANDLE_ENTRY_T {
  DWORD pid;                      // process id
  WCHAR objName[MAX_PATH];        // name of object  
} HANDLE_ENTRY, *PHANDLE_ENTRY;
 
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define DUPLICATE_SAME_ATTRIBUTES   0x00000004 
#define NtCurrentProcess() ( (HANDLE) -1 )
 
// allocate memory
LPVOID xmalloc (SIZE_T dwSize) {
    return HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// re-allocate memory
LPVOID xrealloc (LPVOID lpMem, SIZE_T dwSize) { 
    return HeapReAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, lpMem, dwSize);
}

// free memory
void xfree (LPVOID lpMem) {
    HeapFree (GetProcessHeap(), 0, lpMem);
}

PWCHAR pid2name(DWORD pid) {
    HANDLE         hSnap;
    BOOL           bResult;
    PROCESSENTRY32 pe32;
    PWCHAR         name;
    
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnap != INVALID_HANDLE_VALUE) {
      pe32.dwSize = sizeof(PROCESSENTRY32);
      
      bResult = Process32First(hSnap, &pe32);
      while (bResult) {
        if (pe32.th32ProcessID == pid) {
          name = pe32.szExeFile;
          break;
        }
        bResult = Process32Next(hSnap, &pe32);
      }
      CloseHandle(hSnap);
    }
    return name;
}

/**
 *
 *  Enables or disables a named privilege in token
 *  Returns TRUE or FALSE
 *
 */
BOOL SetPrivilege(wchar_t szPrivilege[], BOOL bEnable) {
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;
    
    bResult = OpenProcessToken(GetCurrentProcess(), 
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if (bResult) {    
      bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);
      if (bResult) {
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;

        bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
      }
      CloseHandle(hToken);
    }
    return bResult;
}

PHANDLE_ENTRY GetHandleList(VOID) 
{
    pNtQuerySystemInformation  NtQuerySystemInformation;
    pNtQueryObject             NtQueryObject;
    
    ULONG                      len=0, total=0, he_size=0, cnt=0;
    NTSTATUS                   status;
    LPVOID                     list=NULL;    
    PHANDLE_ENTRY              he=NULL;
    DWORD                      i;
    HANDLE                     hProcess, hObject;
    OBJECT_BASIC_INFORMATION   obi;
    POBJECT_TYPE_INFORMATION   t;
    POBJECT_NAME_INFORMATION   n;
    
    PSYSTEM_HANDLE_INFORMATION h;
    
    NtQuerySystemInformation = 
        (pNtQuerySystemInformation)GetProcAddress(
        GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");

    NtQueryObject = 
        (pNtQueryObject)GetProcAddress(
        GetModuleHandle(L"ntdll"), "NtQueryObject");
        
    if (!NtQuerySystemInformation || 
        !NtQueryObject) {
      // we couldn't resolve API address
      return NULL;
    }
    
    SetPrivilege(SE_DEBUG_NAME, TRUE);
    
    list = xmalloc(2048);
    
    do {
      len += 2048;
      list = xrealloc (list, len);
      
      if (list==NULL) {
        // we couldn't reallocate memory
        break;
      }
      status = NtQuerySystemInformation(SystemHandleInformation, 
          list, len, &total);
          
    } while (status == STATUS_INFO_LEN_MISMATCH);
    
    if (!NT_SUCCESS(status)) {
      // we were unable to obtain list of process
      xfree(list);
      return NULL;
    }
    
    h       = (PSYSTEM_HANDLE_INFORMATION)list;
    he_size = sizeof(HANDLE_ENTRY);
    he      = xmalloc(he_size);

    // for each handle
    for (i=0; i<h->HandleCount && he != NULL; i++) 
    {
      // skip system
      if (h->Handles[i].ProcessId == 4) continue;
      
      // open the process
      hProcess = OpenProcess(PROCESS_DUP_HANDLE, 
         FALSE, h->Handles[i].ProcessId);
         
      if (hProcess != NULL) 
      {
        // try duplicate handle
        status = DuplicateHandle(hProcess, 
            (HANDLE)h->Handles[i].Handle, GetCurrentProcess(), 
            &hObject, 0, FALSE, DUPLICATE_SAME_ACCESS);
            
        if (status)            
        {
          // query basic info
          status = NtQueryObject(hObject, 
              ObjectBasicInformation, &obi, sizeof(obi), &len);
              
          if (NT_SUCCESS(status)) 
          {
            // skip object if there's no name
            if (obi.NameInformationLength !=0) 
            {                         
              // query the type
              len = obi.TypeInformationLength + 2;
              t = (POBJECT_TYPE_INFORMATION)xmalloc(len);
              
              if (t != NULL) { 
                status = NtQueryObject(hObject, 
                    ObjectTypeInformation, t, len, &len);
                    
                if (NT_SUCCESS(status)) {
                  // skip object if it isn't a mutant
                  if (lstrcmpi(t->Name.Buffer, L"Mutant")!=0) {
                    xfree(t);
                    continue;
                  }
                }
                xfree(t);            
              }
              
              // query the name
              len = obi.NameInformationLength + 2;          
              n = (POBJECT_NAME_INFORMATION)xmalloc(len);
                
              if (n != NULL) {
                status = NtQueryObject(hObject, 
                    ObjectNameInformation, n, len, &len);
                    
                if (NT_SUCCESS(status)) {
                  he[cnt].pid = h->Handles[i].ProcessId;
                  lstrcpy(he[cnt].objName, n->Name.Buffer);
                }
                xfree(n);
              }
              
              // update list
              he_size += sizeof(HANDLE_ENTRY);
              he = xrealloc(he, he_size);
              cnt++;
              
              if (he==NULL) {
                break;
              }         
            }              
          }
          // close object
          CloseHandle(hObject);        
        }
        // close process
        CloseHandle(hProcess);           
      }      
    }    
    xfree(list);
    return he;
}

int main(void)
{
    PHANDLE_ENTRY he;  
    PHANDLE_ENTRY list = GetHandleList();
    PWCHAR        p;
    
    if (list==NULL) {
      wprintf (L"Unable to retrieve list of handles\n");
      return 0;
    }
    
    wprintf (L"List of handles\n");
    wprintf (L"=================\n");
    
    for (he=list; he->pid != 0; he++) {
      p = wcsrchr(he->objName, L'\\') + 1;
      wprintf (L"%s:[%i] - %s\n", pid2name(he->pid), he->pid, p);
    }
    xfree(list);  
    return 0;
}