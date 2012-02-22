#define WIN32_NO_STATUS
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <wchar.h>
typedef LONG NTSTATUS;
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#define MAX_FILES 1500
#define MAX_FILE_NAME 255

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_VALID_ATTRIBUTES    0x000001F2L

#define SE_DEBUG_PRIVILEGE        20

typedef struct _UNICODE_STRING
{
    WORD Length;
    WORD MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING    ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

struct State
{
    int status;
    int validFiles;
    int pe_16;
    int pe_64;
    int allFiles;
    int unknownFiles;
    FILE *logDescr;
    bool FlagOK;
};

int CheckFile(char *fileName);
void WriteToLog(char *fileName, State &st);


int main(int argc, char *argv[])
{
    WIN32_FIND_DATA FindData;
    HANDLE searchHandle;
    bool flagOK = false;

    char logName[MAX_FILE_NAME];
    GetCurrentDirectory(MAX_FILE_NAME, logName);        // default name for log  \cur_dir\log.txt
    strcat(logName, "/log.txt");                        // if /r= flag not set

    State st;
    ZeroMemory(&st, sizeof(st));
    if (argc < 2)
    {
        printf ("\nusage: %s folder_name [/o /r=log.txt]", argv[0]);
        return 0;
    }
    for (int i = 2; argv[i]; i++)                        // cmd args processing
    {
        char *pLogName = NULL;
        if ( !strcmp(argv[i], "/o") )
        {
            st.FlagOK = true;
        } 
        else if ( pLogName = strstr(argv[i], "/r=") )
        {
            GetCurrentDirectory(MAX_FILE_NAME, logName);
            strcat(logName, "/");
            strcat(logName, pLogName+3);
        }
    }

    if ( !(st.logDescr = fopen(logName, "w+")) )
    {
        printf("\nCan't open file %s\n", logName);
        return EXIT_FAILURE;
    }

    char szDir[MAX_FILE_NAME];
    strcpy(szDir, argv[1]);
    strcat(szDir, "/*");
    if ( (searchHandle = FindFirstFile(szDir, &FindData)) == INVALID_HANDLE_VALUE )
    {
        printf("\nCan't open dir %s!\n", szDir);
        return EXIT_FAILURE;
    }

    strcat(argv[1], "/");
    while ( FindNextFile(searchHandle, &FindData) )
    {
        if ( FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY )
            continue;
        char fileName[MAX_FILE_NAME];
        strcpy(fileName, argv[1]);
        strcat(fileName, FindData.cFileName);

        st.status = CheckFile(fileName);
        WriteToLog(fileName, st);
        printf(".");
        st.allFiles++;
    }
    fprintf(st.logDescr, "\n---------------------------------------------------------------------");
    fprintf(st.logDescr, "\nvalid - %d, bad - %d, 16bit - %d 64_bit - %d, unknown - %d, all - %d\n", \
        st.validFiles, (st.allFiles - st.validFiles - st.pe_64 - st.pe_16 - st.unknownFiles)/*bad*/, \
        st.pe_16, st.pe_64, st.unknownFiles, st.allFiles);
    fclose(st.logDescr);
    //system("pause");
    return EXIT_SUCCESS;
} 

typedef int (WINAPI *pNtCreateSection)(PHANDLE SectionHandle,
                                       ACCESS_MASK DesiredAccess,
                                       POBJECT_ATTRIBUTES ObjectAttributes,
                                       PLARGE_INTEGER MaximumSize,
                                       ULONG SectionPageProtection,
                                       ULONG AllocationAttributes,
                                       HANDLE FileHandle
                                       );

typedef int (WINAPI *pRtlAdjustPrivilege)(ULONG   Privilege,
                                          BOOLEAN  Enable,
                                          BOOLEAN  CurrentThread,
                                          PBOOLEAN Enabled
                                          );

int CheckFile(char *fileName)
{
    int status;
    WCHAR objName[MAX_FILE_NAME] = L"myObject";
    HANDLE hFile = CreateFile(fileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if ( hFile == INVALID_HANDLE_VALUE)
    {
        printf("error: %d for file %s\n", GetLastError(), fileName);
        return -1;
    }
    HANDLE phSect;
    ACCESS_MASK DesiredAccess = SECTION_ALL_ACCESS;
    OBJECT_ATTRIBUTES OA;
    UNICODE_STRING obj;

    POBJECT_ATTRIBUTES pObjectAttributes = &OA;
    obj.Buffer = objName;
    obj.Length = wcslen(objName);
    obj.MaximumLength = MAX_FILE_NAME;
    pObjectAttributes->ObjectName = &obj;
    pObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
    pObjectAttributes->RootDirectory = NULL;
    pObjectAttributes->SecurityDescriptor = NULL;
    pObjectAttributes->SecurityQualityOfService = NULL;
    pObjectAttributes->Attributes = OBJ_CASE_INSENSITIVE;

    LARGE_INTEGER MaxSize;
    MaxSize.LowPart = 1024;
    MaxSize.HighPart = 0;
    pNtCreateSection pMyNtCreateSection;
    pRtlAdjustPrivilege pMyRtlAdjustPrivilege;
    pMyRtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlAdjustPrivilege");
    pMyNtCreateSection = (pNtCreateSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateSection");

    BOOLEAN PA = false;
    PBOOLEAN PrevAccess = &PA;

    status = pMyRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, 0, PrevAccess);
    status =  pMyNtCreateSection(&phSect, DesiredAccess, NULL, &MaxSize, PAGE_READONLY, SEC_IMAGE, hFile);

    CloseHandle(hFile);
    return status;
}

void WriteToLog(char *fileName, State &st)
{
    switch ( st.status )
    {
        case 0:
            //printf("\n[+] valid file %s", fileName);
            fprintf(st.logDescr, "\n%s : ok ([+] valid file)", fileName);
            st.validFiles++;
            break;
        case STATUS_INVALID_IMAGE_NOT_MZ:
            //printf("\n[-] file has no MZ %s", fileName);
            fprintf(st.logDescr, "\n%s : bad ([-] file has no MZ)", fileName);
            break;
        case STATUS_INVALID_FILE_FOR_SECTION:
            //printf("\n[-] {Bad File} The attributes... for file %s",  fileName);
            fprintf(st.logDescr, "\n%s : bad ([-] {Bad File})",  fileName);
            break;
        case STATUS_SECTION_TOO_BIG:
            //printf("\n[-] {Section Too Large} for file %s",  fileName);
            fprintf(st.logDescr, "\n%s : bad ([-] {Section Too Large})",  fileName);
            break;
        case STATUS_INVALID_IMAGE_FORMAT:
            //printf("\n[-] {Bad Image} )", fileName);
            fprintf(st.logDescr, "\n%s : bad ([-] {Bad Image})", fileName);
            break;
        case STATUS_INVALID_IMAGE_PROTECT:
            //printf("\n[!] {e_lfarlc problem dos header (16 bit)} )", fileName);
            fprintf(st.logDescr, "\n%s : pe_16 ([!] {e_lfarlc problem dos header (16 bit)})", fileName);
            st.pe_16++;
            break;
        case STATUS_INVALID_IMAGE_WIN_16:
            //printf("\n[!] {16-bit Windows image.} )", fileName);
            fprintf(st.logDescr, "\n%s : pe_16 ([!] {16-bit Windows image.})", fileName);
            st.pe_16++;
            break;
        case STATUS_INVALID_IMAGE_WIN_64:
            //printf("\n[!] {64-bit Windows image.} )", fileName);
            fprintf(st.logDescr, "\n%s : pe_64 ([!] {64-bit Windows image.})", fileName);
            st.pe_64++;
            break;
        case (-1):
            fprintf(st.logDescr, "\n%s : unknown ([-] {got INVALID_HANDLE_VALUE from CreateFile})", fileName);
            st.unknownFiles++;
            break;
        default:
            //printf("\n[-] unknown error %#X )", status, fileName);
            fprintf(st.logDescr, "\n%s : unknown ([-] unknown error %#X )", st.status, fileName);
            st.unknownFiles++;
            break;
    }
}