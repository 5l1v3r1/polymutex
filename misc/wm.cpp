
#include <windows.h>
#include <stdio.h>

int main(void)
{
   const char szUniqueNamedMutex[] = "com_mycompany_apps_appname";
   HANDLE hHandle = CreateMutex( NULL, TRUE, szUniqueNamedMutex );
   if( ERROR_ALREADY_EXISTS == GetLastError() )
   {
      // Program already running somewhere
      return(1); // Exit program
   }

   // Program runs...
   printf ("process id is %i\n", GetCurrentProcessId());
   
   system("pause");
   // Upon app closing:
   ReleaseMutex( hHandle ); // Explicitly release mutex
   CloseHandle( hHandle ); // close handle before terminating
   return( 1 );
}
