#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <winnt.h>

#define MAX_FILES 1500
#define MAX_FILE_NAME 255

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_VALID_ATTRIBUTES    0x000001F2L

#define 	SE_DEBUG_PRIVILEGE  20

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING	ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


int CheckFile(char *fileName);

int main(int argc, char *argv[])
{
	WIN32_FIND_DATA fd;
	HANDLE searchHandle;
	//if (argc != 2)
	//{
	//	printf ("\nusage: %s folder_name", argv[0]);
	//	return 0;
	//}
	char szDir[MAX_FILE_NAME];

	strcpy(szDir, argv[1]);
	strcat(szDir, "\\*");
	if ( (searchHandle = FindFirstFile(szDir, &fd)) == INVALID_HANDLE_VALUE )
	{
		printf("\nCan't open dir!\n");
		return 0;
	}

	strcat(argv[1], "\\");
	int status;
    int validFiles = 0;
    int allFiles = 0;
    int unknownFiles = 0;
	while ( FindNextFile(searchHandle, &fd) )
	{
		char fileName[MAX_FILE_NAME];
		strcpy(fileName, argv[1]);
		strcat(fileName, fd.cFileName);
		if ( (status = CheckFile(fileName)) == -1)
            printf("\n[-] %s, status = %#X", fd.cFileName, status);
        else if ( status == 0 )
        {
			printf("\n[+] valid file %s", fd.cFileName);
            validFiles++;
        }
		else if ( status == 0xC000012F )
            printf("\n[-] file has no MZ %s", fd.cFileName);
        else if ( status == 0xC0000040 )
            printf("\n[-] {Section Too Large} for file %s",  fd.cFileName);
        else if ( status == 0xC000007B )
            printf("\n[-] {Bad Image} for file %s", fd.cFileName);
/*{Bad Image} %hs is either not designed to\ run on Windows or it contains an error. 
Try installing the program again using the original installation media or contact your system 
administrator or the software vendor for support.*/
        else if ( status == 0xC0000130 )
            printf("\n[-] {e_lfarlc problem dos header} for file %s", fd.cFileName);
/*The specified image file did not have the correct format: it did not have a proper e_lfarlc in the MZ header.*/
        else if ( status == 0xC000035A )
        {
            printf("\n[!] {it appears to be a 64-bit Windows image.} for file %s", fd.cFileName);
            unknownFiles++;
        }
        else 
        {
            printf("\n[!] unknown error %#X for file %s", status, fd.cFileName);
            unknownFiles++;
        }
        allFiles++;

        //if ( (counter++ % 500) == 0)
	    //system("pause");
	}
    printf("\n---------------------------------------------------------------------");
    printf("\nvalid - %d, invalid - %d, unknown - %d, all - %d\n", \
        validFiles, (allFiles-validFiles-unknownFiles), unknownFiles, allFiles);
    //system("pause");
	return 0;
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
		int err = GetLastError();
		return -1;
	}
	HANDLE phSect;
	ACCESS_MASK DesiredAccess = SECTION_MAP_READ;
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
	pNtCreateSection pNt;
	pRtlAdjustPrivilege pRtl;
	pRtl = (pRtlAdjustPrivilege)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlAdjustPrivilege");
	pNt = (pNtCreateSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateSection");

	BOOLEAN PA = false;
	PBOOLEAN PrevAccess = &PA;

	status = pRtl(SE_DEBUG_PRIVILEGE, true, 0, PrevAccess);
	status =  pNt(&phSect, DesiredAccess, NULL, &MaxSize, PAGE_READONLY, SEC_IMAGE, hFile);
	if (status == 0)
		return 0;

    CloseHandle(hFile);
	return status;
}




