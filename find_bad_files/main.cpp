#define WIN32_NO_STATUS
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <wchar.h>
typedef LONG NTSTATUS;
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#define VERSION_                0.4f                  
#define MAX_FILE_NAME           255

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_VALID_ATTRIBUTES    0x000001F2L

#define SE_DEBUG_PRIVILEGE      20

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
    int not_mz;
    int pe_16;
    int pe_64;
    int allFiles;
    int unknownFiles;
    FILE *logDescr;
};

static int CheckFile(const char *fileName);
static void WriteToLog(const char *fileName, State &st);
static void ProcessDir(char *dir_mask, State &st);

int main(int argc, char *argv[])
{
    const char * logName = "log.txt"; //default

    State st;
    ZeroMemory(&st, sizeof(st));
    if (argc < 2)
    {
        printf ("usage: %s [/r=log.txt]  folder_name...\n", argv[0]);
        return EXIT_SUCCESS;
    }
    char ** argp = &argv[1];

    for (; *argp; ++argp)               // logname arg processing
    {
        if (0 == strncmp(*argp, "/r=", 3))
        {
            logName = *argp + 3;
        }
        else
            break;
    }

    st.logDescr = fopen(logName, "w+");
    if (!st.logDescr)
    {
        printf("Can't open file %s\n", logName);
        return EXIT_FAILURE;
    }

    for (; *argp; ++argp)               // paths
        ProcessDir(*argp, st);

    fprintf(st.logDescr, "---------------------------------------------------------------------\n");
    fprintf(st.logDescr, "valid - %d, bad - %d, not_mz - %d, 16bit - %d 64_bit - %d, unknown - %d, all - %d\nversion %.2f by yurket",
            st.validFiles, (st.allFiles - st.validFiles - st.pe_64 - st.pe_16 - st.unknownFiles - st.not_mz)/*bad*/,
            st.not_mz, st.pe_16, st.pe_64, st.unknownFiles, st.allFiles, VERSION_);
    fclose(st.logDescr);
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

int CheckFile(const char *fileName)
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
    status = pMyRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, 0, &PA);
    status =  pMyNtCreateSection(&phSect, DesiredAccess, NULL, &MaxSize, PAGE_READONLY, SEC_IMAGE, hFile);

    CloseHandle(hFile);
    return status;
}

void WriteToLog(const char *fileName, State &st)
{
    switch ( st.status )
    {
        case 0:
            fprintf(st.logDescr, "%s : ok ([+] valid file)\n", fileName);
            st.validFiles++;
            break;
        case STATUS_INVALID_IMAGE_NOT_MZ:
            fprintf(st.logDescr, "%s : not_mz ([!] file has no MZ)\n", fileName);
            st.not_mz++;
            break;
        case STATUS_INVALID_FILE_FOR_SECTION:
            fprintf(st.logDescr, "%s : bad ([-] {Bad File})\n",  fileName);
            break;
        case STATUS_SECTION_TOO_BIG:
            fprintf(st.logDescr, "%s : bad ([-] {Section Too Large})\n",  fileName);
            break;
        case STATUS_INVALID_IMAGE_FORMAT:
            fprintf(st.logDescr, "%s : bad ([-] {Bad Image})\n", fileName);
            break;
        case STATUS_INVALID_IMAGE_PROTECT:
            fprintf(st.logDescr, "%s : pe_16 ([!] {e_lfarlc problem dos header (16 bit)})\n", fileName);
            st.pe_16++;
            break;
        case STATUS_INVALID_IMAGE_WIN_16:
            fprintf(st.logDescr, "%s : pe_16 ([!] {16-bit Windows image.})\n", fileName);
            st.pe_16++;
            break;
        case STATUS_INVALID_IMAGE_WIN_64:
            fprintf(st.logDescr, "%s : pe_64 ([!] {64-bit Windows image.})\n", fileName);
            st.pe_64++;
            break;
        case (-1):
            fprintf(st.logDescr, "%s : unknown ([-] {got INVALID_HANDLE_VALUE from CreateFile})\n", fileName);
            st.unknownFiles++;
            break;
        default:
            fprintf(st.logDescr, "%s : unknown ([-] unknown error %#X )\n", fileName, st.status);
            st.unknownFiles++;
            break;
    }
}

void ProcessDir(char *argp, State &st)
{
    WIN32_FIND_DATA FindData;
    HANDLE searchHandle;
    char dir_mask[MAX_FILE_NAME];

    _snprintf(dir_mask, sizeof (dir_mask) - 1, "%s/*", argp);
    dir_mask[sizeof (dir_mask) - 1] = '\0';
    searchHandle = FindFirstFile(dir_mask, &FindData);
        if ( searchHandle == INVALID_HANDLE_VALUE )
        {
            printf("Can't open dir %s!\n", dir_mask);
        }

        while (FindNextFile(searchHandle, &FindData))
        {
            char filepath[MAX_FILE_NAME];
            if (FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
            {
                if (strcmp(FindData.cFileName, "..") == 0)
                    continue;
                else
                {
                    char subdir[MAX_FILE_NAME];
                    _snprintf(subdir, sizeof(subdir) - 1, "%s/%s", argp, FindData.cFileName);
                    ProcessDir(subdir, st);
                    continue;
                }
            }
            _snprintf(filepath, sizeof (filepath) - 1, "%s/%s", argp, FindData.cFileName);
            filepath[sizeof (filepath) - 1] = '\0';

            st.status = CheckFile(filepath);
            WriteToLog(filepath, st);
            printf(".");
            st.allFiles++;
        }
}