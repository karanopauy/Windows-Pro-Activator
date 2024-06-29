#include <windows.h>
#include <iostream>
#include <conio.h>
using namespace std;
bool IsUserAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

void RequestAdminPrivileges()
{
    if (!IsUserAdmin())
    {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath)))
        {
            SHELLEXECUTEINFOW sei = {sizeof(sei)};
            sei.lpVerb = L"runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;

            if (!ShellExecuteExW(&sei))
            {
                DWORD dwError = GetLastError();
                if (dwError == ERROR_CANCELLED)
                {
                    std::wcout << L"User declined the elevation request.\n";
                }
                else
                {
                    std::wcout << L"Error requesting elevation: " << dwError << L"\n";
                }
            }
            else
            {
                exit(0);
            }
        }
    }
}

int main()
{
    RequestAdminPrivileges();

    int error;
    error = system("slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX");
    if (error == 0)
    {
        error = system("slmgr /skms kms8.msguides.com");
        if (error == 0)
        {
            error = system("slmgr /ato");
            if (error == 0)
            {
                cout << " Success!";
            }
            else
            {
                cout << " Error!";
            }
        }
        else
        {
            cout << " Error!";
        }
    }
    else
    {
        cout << " Error! Launch this program as ADMIN!";
        _getch();
        exit(0);
    }
    cout << " Successfully activated the windows. Please enter any key to exit...";
    _getch();

    return 0;
}
