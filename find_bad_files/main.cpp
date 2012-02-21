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
void WriteToLog(FILE *logDescr, char *fileName, bool FlagOk);


int main(int argc, char *argv[])
{
	WIN32_FIND_DATA FindData;
	HANDLE searchHandle;
	bool flagOK = false;

	char logName[MAX_FILE_NAME];
	GetCurrentDirectory(MAX_FILE_NAME, logName);		// default name for log  \cur_dir\log.txt
	strcat(logName, "\\log.txt");						// if /r= flag not set
	FILE *logDescr = NULL;

	if (argc < 2)
	{
		printf ("\nusage: %s folder_name [/o /r=log.txt]", argv[0]);
		return 0;
	}
	for (int i = 2; argv[i]; i++)						// cmd args processing
	{
		char *pLogName = NULL;
		if ( !stricmp(argv[i], "/o") )
		{
			flagOK = true;
		} 
		else if ( pLogName = strstr(argv[i], "/r=") )
		{
			GetCurrentDirectory(MAX_FILE_NAME, logName);
			strcat(logName, "\\");
			strcat(logName, pLogName+3);
		}
	}

	if ( !(logDescr = fopen(logName, "w+")) )
	{
		printf("\nCan't open file %s\n", logName);
		return -1;
	}

	char szDir[MAX_FILE_NAME];
	strcpy(szDir, argv[1]);
	strcat(szDir, "\\*");
	if ( (searchHandle = FindFirstFile(szDir, &FindData)) == INVALID_HANDLE_VALUE )
	{
		printf("\nCan't open dir!\n");
		return 0;
	}

	strcat(argv[1], "\\");
	int status;
	int validFiles = 0;
	int pe_16_64 = 0;
	int allFiles = 0;
	int unknownFiles = 0;
	FindNextFile(searchHandle, &FindData);						// omitting ".."
	while ( FindNextFile(searchHandle, &FindData) )
	{
		char fileName[MAX_FILE_NAME];
		strcpy(fileName, argv[1]);
		strcat(fileName, FindData.cFileName);
		bool OkFlag = false, DeadFlag = false, flag16_64_bit = false;


		if (flagOK)
			switch ( (status = CheckFile(fileName)) )			// barely logging
			{
			case 0:
				fprintf(logDescr, "\n%s : ok", fileName);
				validFiles++;
				break;
			case 0xC000012F: case 0xC0000040: case 0xC000007B:
				fprintf(logDescr, "\n%s : dead", fileName);
				break;
			case 0xC0000130: case 0xC0000131: case 0xC000035A:
				fprintf(logDescr, "\n%s : pe_16_64", fileName);
				pe_16_64++;
				break;
			default:
				fprintf(logDescr, "\n%s : unknown ", fileName);
				unknownFiles++;
				break;
			}
		else													// descriptive log
			switch ( (status = CheckFile(fileName)) )
			{
			case 0:
				printf("\n[+] valid file %s", FindData.cFileName);
				fprintf(logDescr, "\n[+] valid file %s", FindData.cFileName);
				validFiles++;
				break;
			case 0xC000012F:
				printf("\n[-] file has no MZ %s", FindData.cFileName);
				fprintf(logDescr, "\n[-] file has no MZ %s", FindData.cFileName);
				break;
			case 0xC0000040:
				printf("\n[-] {Section Too Large} for file %s",  FindData.cFileName);
				fprintf(logDescr, "\n[-] {Section Too Large} for file %s",  FindData.cFileName);
				break;
			case 0xC000007B:
				printf("\n[-] {Bad Image} for file %s", FindData.cFileName);
				fprintf(logDescr, "\n[-] {Bad Image} for file %s", FindData.cFileName);
				break;
			case 0xC0000130:
				printf("\n[!] {e_lfarlc problem dos header (16 bit)} for file %s", FindData.cFileName);
				fprintf(logDescr, "\n[!] {e_lfarlc problem dos header (16 bit)} for file %s", FindData.cFileName);
				pe_16_64++;
				break;
			case 0XC0000131:
				printf("\n[!] {16-bit Windows image.} for file %s", FindData.cFileName);
				fprintf(logDescr, "\n[!] {16-bit Windows image.} for file %s", FindData.cFileName);
				pe_16_64++;
				break;
			case 0xC000035A:
				printf("\n[!] {64-bit Windows image.} for file %s", FindData.cFileName);
				fprintf(logDescr, "\n[!] {64-bit Windows image.} for file %s", FindData.cFileName);
				pe_16_64++;
				break;
			default:
				printf("\n[-] unknown error %#X for file %s", status, FindData.cFileName);
				fprintf(logDescr, "\n[-] unknown error %#X for file %s", status, FindData.cFileName);
				unknownFiles++;
				break;
			}
		allFiles++;

		//if ( (allFiles % 500) == 0)
		// system("pause");
	}
	fprintf(logDescr, "\n---------------------------------------------------------------------");
	fprintf(logDescr, "\nvalid - %d, 16/64_bit - %d, unknown - %d, all - %d\n", \
		validFiles, pe_16_64, unknownFiles, allFiles);
	fclose(logDescr);
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
	pNtCreateSection pNt;
	pRtlAdjustPrivilege pRtl;
	pRtl = (pRtlAdjustPrivilege)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlAdjustPrivilege");
	pNt = (pNtCreateSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateSection");

	BOOLEAN PA = false;
	PBOOLEAN PrevAccess = &PA;

	status = pRtl(SE_DEBUG_PRIVILEGE, true, 0, PrevAccess);
	status =  pNt(&phSect, DesiredAccess, NULL, &MaxSize, PAGE_READONLY, SEC_IMAGE, hFile);

	CloseHandle(hFile);
	return status;
}

void WriteToLog(FILE *logDescr, char *fileName, bool FlagOk)
{

}