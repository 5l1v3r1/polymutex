

/*"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography"
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Cryptography\MachineGuid
*/

#include <stdio.h>
#include <stdint.h>
#include <Shlwapi.h>
#include <windows.h>

#pragma comment (lib, "shlwapi.lib")

int main(void) {
  DWORD   serial;
  DWORD   n;
  char    guid[MAX_PATH];
  HKEY    hSubKey;
  
  n=sizeof(guid);

  RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
      "SOFTWARE\\Microsoft\\Cryptography", 0, 
      KEY_READ | KEY_WOW64_64KEY, &hSubKey);
      
  RegQueryValueEx(hSubKey, "MachineGuid", NULL,
          NULL, (LPBYTE)guid, &n);
          
  RegCloseKey(hSubKey);        
  printf ("MachineGuid: %s\n", guid);
  
  n=sizeof(serial);      
  GetVolumeInformation(NULL, NULL, 0, &serial, &n, 0, 0, 0);
  printf ("Serial Number: %ld\n", serial);
  return 0;
}
