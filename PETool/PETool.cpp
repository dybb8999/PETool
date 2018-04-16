// PETool.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include "tools/PEHeaderAnalysis.h"

using namespace std;

void ShowInfo();
char *GetMachine(WORD machine);
char *GetCharacteristics(WORD Characteristics);
char *GetSubSystem(WORD subSystem);
void ShowSections();
void ShowDirection();
void ShowImportTable();
void ShowExportTable();
char* GetSectionsCharacteristics(DWORD Characteristics);

int main(int argc, char**argv)
{
	string exeFile;
	if (argc >= 2)
	{
		exeFile = argv[1];
	}
	else
	{
		cout << "Please input a exefile:" << endl;
		getline(cin, exeFile);
	}
	setlocale(LC_ALL, "chs");//让程序支持UTF-16中文的输出

	if (CPEHeaderAnalysis::GetInstance()->LoadFile(exeFile.c_str()) == false)
	{
		cout << "文件打开失败" << endl;
		return -1;
	}

	if (CPEHeaderAnalysis::GetInstance()->Analysis() == false)
	{
		cout << "文件分析失败， 该文件具有PE格式？" << endl;
		return -1;
	}

	int select;
	ShowInfo();

	do 
	{
		printf_s("1.显示区块信息 2.显示数据目录 3.导入表 4.导出表 0退出\n");
		if (cin.fail() == true)
		{
			break;
		}

		cin >> select;
		switch (select)
		{
		case 1://区块显示
			ShowSections();
			break;

		case 2:
			ShowDirection();
			break;

		case 3:
			ShowImportTable();
			break;

		case 4:
			ShowExportTable();
			break;
		case 0:
			return 0;
		default :
			break;
		}
	} while (1);

    return 0;
}

void ShowInfo()
{
	const IMAGE_SECTION_HEADER* pHeadSection;
	bool isX64 = CPEHeaderAnalysis::GetInstance()->isX64();
	pHeadSection = CPEHeaderAnalysis::GetInstance()->GetIMAGE_SECTION_HEADER();
	if (true == isX64)
	{
		const IMAGE_NT_HEADERS64* pHead = nullptr;
		pHead = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64();
		printf_s("--------------------------------------\n");
		printf_s("文件：%S\n", CPEHeaderAnalysis::GetInstance()->GetFile());
		printf_s("运行平台：%s\n", GetMachine(pHead->FileHeader.Machine));
		printf_s("区块数目：%u\n", pHead->FileHeader.NumberOfSections);
		printf_s("文件属性：%s\n", GetCharacteristics(pHead->FileHeader.Characteristics));
		printf_s("子系统：%s\n", GetSubSystem(pHead->OptionalHeader.Subsystem));
		printf_s("文件对齐大小：0x%08X\n", pHead->OptionalHeader.FileAlignment);
		printf_s("内存对齐大小：0x%08X\n", pHead->OptionalHeader.SectionAlignment);
		printf_s("--------------------------------------\n");
	}
	else
	{
		const IMAGE_NT_HEADERS32* pHead = nullptr;
		pHead = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32();
		printf_s("--------------------------------------\n");
		printf_s("文件：%S\n", CPEHeaderAnalysis::GetInstance()->GetFile());
		printf_s("运行平台：%s\n", GetMachine(pHead->FileHeader.Machine));
		printf_s("区块数目：%u\n", pHead->FileHeader.NumberOfSections);
		printf_s("文件属性：%s\n", GetCharacteristics(pHead->FileHeader.Characteristics));
		printf_s("子系统：%s\n", GetSubSystem(pHead->OptionalHeader.Subsystem));
		printf_s("文件对齐大小：0x%08X\n", pHead->OptionalHeader.FileAlignment);
		printf_s("内存对齐大小：0x%08X\n", pHead->OptionalHeader.SectionAlignment);
		printf_s("--------------------------------------\n");
	}
	
}

char *GetMachine(WORD machine)
{
	if (IMAGE_FILE_MACHINE_I386 == machine)
	{
		return "Intel 386";
	}
	else if (IMAGE_FILE_MACHINE_IA64 == machine)
	{
		return "Intel Itanium";
	}
	else if (IMAGE_FILE_MACHINE_AMD64 == machine)
	{
		return "AMD64 (K8)";
	}
	else if(IMAGE_FILE_MACHINE_R3000 == machine)
	{
		return "MIPS little-endian, 0x160 big-endian";
	}
	else if ((IMAGE_FILE_MACHINE_R4000 == machine)||(IMAGE_FILE_MACHINE_R10000 == machine))
	{
		return "MIPS little-endian";
	}
	else if (IMAGE_FILE_MACHINE_WCEMIPSV2 == machine)
	{
		return "MIPS little-endian WCE v2";
	}
	else if (IMAGE_FILE_MACHINE_ALPHA == machine)
	{
		return "Alpha_AXP";
	}
	else if (IMAGE_FILE_MACHINE_SH3 == machine)
	{
		return "SH3 little-endian";
	}
	else if (IMAGE_FILE_MACHINE_SH3DSP == machine)
	{
		return "IMAGE_FILE_MACHINE_SH3DSP";
	}
	else if (IMAGE_FILE_MACHINE_SH3E == machine)
	{
		return "SH3E little-endian";
	}
	else if (IMAGE_FILE_MACHINE_ARM == machine)
	{
		return "ARM Little-Endian";
	}
	else if (IMAGE_FILE_MACHINE_IA64 == machine)
	{
		return "Intel 64";
	}
	else if (IMAGE_FILE_MACHINE_M32R == machine)
	{
		return "M32R little-endian";
	}
	else if (IMAGE_FILE_MACHINE_EBC == machine)
	{
		return "EFI Byte Code";
	}

	return "Unknown";
}

char *GetCharacteristics(WORD Characteristics)
{
	static char buff[1024] = { 0 };
	buff[0] = 0;
	if ((Characteristics&IMAGE_FILE_RELOCS_STRIPPED) == IMAGE_FILE_RELOCS_STRIPPED)
	{
		strcat_s(buff, "IMAGE_FILE_RELOCS_STRIPPED|");
	}

	if ((Characteristics&IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		strcat_s(buff, "IMAGE_FILE_EXECUTABLE_IMAGE|");
	}

	if ((Characteristics&IMAGE_FILE_LINE_NUMS_STRIPPED) == IMAGE_FILE_LINE_NUMS_STRIPPED)
	{
		strcat_s(buff, "IMAGE_FILE_LINE_NUMS_STRIPPED|");
	}

	if ((Characteristics&IMAGE_FILE_LOCAL_SYMS_STRIPPED) == IMAGE_FILE_LOCAL_SYMS_STRIPPED)
	{
		strcat_s(buff, "IMAGE_FILE_LOCAL_SYMS_STRIPPED|");
	}

	if ((Characteristics&IMAGE_FILE_AGGRESIVE_WS_TRIM) == IMAGE_FILE_AGGRESIVE_WS_TRIM)
	{
		strcat_s(buff, "IMAGE_FILE_AGGRESIVE_WS_TRIM|");
	}

	if ((Characteristics&IMAGE_FILE_LARGE_ADDRESS_AWARE) == IMAGE_FILE_LARGE_ADDRESS_AWARE)
	{
		strcat_s(buff, "IMAGE_FILE_LARGE_ADDRESS_AWARE|");
	}

	if ((Characteristics&IMAGE_FILE_BYTES_REVERSED_LO) == IMAGE_FILE_BYTES_REVERSED_LO)
	{
	strcat_s(buff, "IMAGE_FILE_BYTES_REVERSED_LO|");
	}

	if ((Characteristics&IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE)
	{
		strcat_s(buff, "IMAGE_FILE_32BIT_MACHINE|");
	}

	if ((Characteristics&IMAGE_FILE_DEBUG_STRIPPED) == IMAGE_FILE_DEBUG_STRIPPED)
	{
		strcat_s(buff, "IMAGE_FILE_DEBUG_STRIPPED|");
	}

	if ((Characteristics&IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) == IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
	{
		strcat_s(buff, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP|");
	}

	if ((Characteristics&IMAGE_FILE_NET_RUN_FROM_SWAP) == IMAGE_FILE_NET_RUN_FROM_SWAP)
	{
		strcat_s(buff, "IMAGE_FILE_NET_RUN_FROM_SWAP|");
	}

	if ((Characteristics&IMAGE_FILE_SYSTEM) == IMAGE_FILE_SYSTEM)
	{
		strcat_s(buff, "IMAGE_FILE_SYSTEM|");
	}

	if ((Characteristics&IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		strcat_s(buff, "IMAGE_FILE_DLL|");
	}

	if ((Characteristics&IMAGE_FILE_UP_SYSTEM_ONLY) == IMAGE_FILE_UP_SYSTEM_ONLY)
	{
		strcat_s(buff, "IMAGE_FILE_UP_SYSTEM_ONLY|");
	}

	if ((Characteristics&IMAGE_FILE_BYTES_REVERSED_HI) == IMAGE_FILE_BYTES_REVERSED_HI)
	{
		strcat_s(buff, "IMAGE_FILE_BYTES_REVERSED_HI|");
	}

	buff[strlen(buff) - 1] = 0;
	return buff;
}

char *GetSubSystem(WORD subSystem)
{
	if (IMAGE_SUBSYSTEM_NATIVE == subSystem)
	{
		return "IMAGE_SUBSYSTEM_NATIVE";
	}
	else if (IMAGE_SUBSYSTEM_WINDOWS_GUI == subSystem)
	{
		return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
	}
	else if (IMAGE_SUBSYSTEM_WINDOWS_CUI == subSystem)
	{
		return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
	}
	else if (IMAGE_SUBSYSTEM_WINDOWS_CE_GUI == subSystem)
	{
		return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
	}
	else if (IMAGE_SUBSYSTEM_EFI_APPLICATION == subSystem)
	{
		return "IMAGE_SUBSYSTEM_EFI_APPLICATION ";
	}
	else if (IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER == subSystem)
	{
		return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  ";
	}
	else if (IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER == subSystem)
	{
		return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER  ";
	}
	else if (IMAGE_SUBSYSTEM_EFI_ROM == subSystem)
	{
		return "IMAGE_SUBSYSTEM_EFI_ROM";
	}
	else if (IMAGE_SUBSYSTEM_XBOX == subSystem)
	{
		return "IMAGE_SUBSYSTEM_XBOX ";
	}
	else if (IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION == subSystem)
	{
		return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION ";
	}
	else
	{
		return "IMAGE_SUBSYSTEM_UNKNOWN";
	}
}

char* GetSectionsCharacteristics(DWORD Characteristics)
{
	static char buff[1024] = { 0 };
	buff[0] = 0;
	if ((Characteristics&IMAGE_SCN_TYPE_NO_PAD) == IMAGE_SCN_TYPE_NO_PAD)
	{
		strcat_s(buff, "IMAGE_SCN_TYPE_NO_PAD|");
	}

	if ((Characteristics&IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE)
	{
		strcat_s(buff, "IMAGE_SCN_CNT_CODE|");
	}

	if ((Characteristics&IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA)
	{
		strcat_s(buff, "IMAGE_SCN_CNT_INITIALIZED_DATA|");
	}

	if ((Characteristics&IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA)
	{
		strcat_s(buff, "IMAGE_SCN_CNT_UNINITIALIZED_DATA|");
	}

	if ((Characteristics&IMAGE_SCN_LNK_OTHER) == IMAGE_SCN_LNK_OTHER)
	{
		strcat_s(buff, "IMAGE_SCN_LNK_OTHER|");
	}

	if ((Characteristics&IMAGE_SCN_LNK_INFO) == IMAGE_SCN_LNK_INFO)
	{
		strcat_s(buff, "IMAGE_SCN_LNK_INFO|");
	}

	if ((Characteristics&IMAGE_SCN_LNK_REMOVE) == IMAGE_SCN_LNK_REMOVE)
	{
		strcat_s(buff, "IMAGE_SCN_LNK_REMOVE|");
	}

	if ((Characteristics&IMAGE_SCN_LNK_COMDAT) == IMAGE_SCN_LNK_COMDAT)
	{
		strcat_s(buff, "IMAGE_SCN_LNK_COMDAT|");
	}

	if ((Characteristics&IMAGE_SCN_NO_DEFER_SPEC_EXC) == IMAGE_SCN_NO_DEFER_SPEC_EXC)
	{
		strcat_s(buff, "IMAGE_SCN_NO_DEFER_SPEC_EXC|");
	}

	if ((Characteristics&IMAGE_SCN_GPREL) == IMAGE_SCN_GPREL)
	{
		strcat_s(buff, "IMAGE_SCN_GPREL|");
	}

	if ((Characteristics&IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_LOCKED)
	{
		strcat_s(buff, "IMAGE_SCN_MEM_NOT_CACHED|");
	}

	if ((Characteristics&IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_LOCKED)
	{
		strcat_s(buff, "IMAGE_SCN_MEM_SHARED|");
	}

	if ((Characteristics&IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
	{
		strcat_s(buff, "IMAGE_SCN_MEM_EXECUTE|");
	}

	if ((Characteristics&IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ)
	{
		strcat_s(buff, "IMAGE_SCN_MEM_READ|");
	}

	if ((Characteristics&IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)
	{
		strcat_s(buff, "IMAGE_SCN_MEM_WRITE|");
	}

	buff[strlen(buff) - 1] = 0;
	return buff;
}

void ShowSections()
{
	const IMAGE_SECTION_HEADER* sectionHead = CPEHeaderAnalysis::GetInstance()->GetIMAGE_SECTION_HEADER();

	for (int i = 0; i < CPEHeaderAnalysis::GetInstance()->GetSectionNum(); ++i)
	{
		for (int index = 0; index < 8; ++index)
		{
			putchar(sectionHead[i].Name[index]);
		}
		putchar('\n');

		printf_s("  VirtualAddress:0x%08X\t", sectionHead[i].VirtualAddress);
		printf_s("  VirtualSize:0x%08X\n", sectionHead[i].Misc.VirtualSize);
		printf_s("PointerToRawData:0x%08X\t", sectionHead[i].PointerToRawData);
		printf_s("SizeOfRawData:0x%08X\n", sectionHead[i].SizeOfRawData);
		printf_s("Characteristics:%s\n", GetSectionsCharacteristics(sectionHead[i].Characteristics));
		putchar('\n');
	}
}

void ShowDirection()
{
	char *item[] =
	{
		"Export Table:",
		"Import Table:",
		"Resource Table:",
		"Exception Table:",
		"Security Table:",
		"Base relocation Table:",
		"Debug:",
		"Copyright:",
		"Global Ptr:",
		"Thread local storage(TLS):",
		"Load configuration:",
		"Bound Import:",
		"Import Address Table(IAT):",
		"Delay Import:",
		"COM decriptor:"
	};

	if (CPEHeaderAnalysis::GetInstance()->isX64())
	{
		const IMAGE_NT_HEADERS64 *pHead = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64();
		for (int i = 0; i < 14; ++i)
		{
			printf_s("%30s:\t地址:0x%08X\t", item[i], pHead->OptionalHeader.DataDirectory[i].VirtualAddress);
			printf_s("大小:0x%08X\n", pHead->OptionalHeader.DataDirectory[i].Size);
		}
	}
	else
	{
		const IMAGE_NT_HEADERS32 *pHead = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32();
		for (int i = 0; i < 14; ++i)
		{
			printf_s("%30s\t地址:0x%08X\t", item[i], pHead->OptionalHeader.DataDirectory[i].VirtualAddress);
			printf_s("大小:0x%08X\n", pHead->OptionalHeader.DataDirectory[i].Size);
		}

	}
	putchar('\n');
}

void ShowImportTable()
{
	DWORD fileAlignment;
	DWORD sectionAlignment;
	const IMAGE_DATA_DIRECTORY* pDataDirectory;
	if (CPEHeaderAnalysis::GetInstance()->isX64())
	{
		pDataDirectory = &CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64()->OptionalHeader.DataDirectory[1];
		fileAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64()->OptionalHeader.FileAlignment;
		sectionAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64()->OptionalHeader.SectionAlignment;
	}
	else
	{
		pDataDirectory = &CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32()->OptionalHeader.DataDirectory[1];
		fileAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32()->OptionalHeader.FileAlignment;
		sectionAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32()->OptionalHeader.SectionAlignment;
	}

	if (pDataDirectory->Size == 0)
	{
		printf_s("此程序没有导入表\n");
		return;
	}

	//查找所在范围
	const IMAGE_SECTION_HEADER* sectionHead = CPEHeaderAnalysis::GetInstance()->GetIMAGE_SECTION_HEADER();
	int i = 0;
	for (; i < CPEHeaderAnalysis::GetInstance()->GetSectionNum(); ++i)
	{
		if ((sectionHead[i].VirtualAddress <= pDataDirectory->VirtualAddress) &&
			(sectionHead[i].VirtualAddress + sectionHead[i].Misc.VirtualSize >= pDataDirectory->VirtualAddress))
		{
			break;
		}
	}

	if (CPEHeaderAnalysis::GetInstance()->GetSectionNum() == i)
	{
		printf_s("代码有毒，没找到\n");
		return;
	}

	sectionHead += i;

	DWORD dataSize = sectionHead->SizeOfRawData;
	const unsigned char *fileData = CPEHeaderAnalysis::GetInstance()->GetFileData(sectionHead->PointerToRawData, dataSize);
	if (nullptr == fileData)
		return;

	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(fileData + pDataDirectory->VirtualAddress - sectionHead->VirtualAddress);
	for (unsigned i = 0; i < (pDataDirectory->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)); ++i)
	{
		//判断导入表是否为空
		if ((*(DWORD*)&importDescriptor[i]) == 0)
		{
			break;
		}
		printf_s("模块名称：%s\n", (char*)(fileData + importDescriptor[i].Name - sectionHead->VirtualAddress));
		DWORD funcIndex = 0;
		
		DWORD Thunk;
		if (importDescriptor[i].OriginalFirstThunk != 0)
		{
			Thunk = importDescriptor[i].OriginalFirstThunk;
		}
		else
		{
			Thunk = importDescriptor[i].FirstThunk;
		}
		

		while (1)
		{
			//DWORD funcNameAddress = *(((DWORD*)) + funcIndex++);
			DWORD funcNameBase = *((DWORD*)(fileData + Thunk - sectionHead->VirtualAddress)+ funcIndex++);
			if (0 == funcNameBase)
			{
				break;
			}

			if ((funcNameBase & 0x80000000) == 0x80000000)
			{
				printf_s("None, No.%u\n", (unsigned short)funcNameBase);
				continue;
			}
			IMAGE_IMPORT_BY_NAME *funcName = (IMAGE_IMPORT_BY_NAME*)(fileData + funcNameBase - sectionHead->VirtualAddress);

			printf_s("%s\n", funcName->Name);
		}
		putchar('\n');
	}

	CPEHeaderAnalysis::GetInstance()->RemoveFileData(fileData);
	putchar('\n');
}

void ShowExportTable()
{
	DWORD fileAlignment;
	DWORD sectionAlignment;
	const IMAGE_DATA_DIRECTORY* pDataDirectory;
	if (CPEHeaderAnalysis::GetInstance()->isX64())
	{
		pDataDirectory = &CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64()->OptionalHeader.DataDirectory[0];
		fileAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64()->OptionalHeader.FileAlignment;
		sectionAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS64()->OptionalHeader.SectionAlignment;
	}
	else
	{
		pDataDirectory = &CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32()->OptionalHeader.DataDirectory[0];
		fileAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32()->OptionalHeader.FileAlignment;
		sectionAlignment = CPEHeaderAnalysis::GetInstance()->GetIMAGE_NT_HEADERS32()->OptionalHeader.SectionAlignment;
	}

	if (pDataDirectory->Size == 0)
	{
		printf_s("此程序没有导出表\n");
		return;
	}

	//查找所在范围
	const IMAGE_SECTION_HEADER* sectionHead = CPEHeaderAnalysis::GetInstance()->GetIMAGE_SECTION_HEADER();
	int i = 0;
	for (; i < CPEHeaderAnalysis::GetInstance()->GetSectionNum(); ++i)
	{
		if ((sectionHead[i].VirtualAddress <= pDataDirectory->VirtualAddress) &&
			(sectionHead[i].VirtualAddress + sectionHead[i].Misc.VirtualSize >= pDataDirectory->VirtualAddress))
		{
			break;
		}
	}

	sectionHead += i;

	DWORD dataSize = sectionHead->SizeOfRawData;
	const unsigned char *fileData = CPEHeaderAnalysis::GetInstance()->GetFileData(sectionHead->PointerToRawData, dataSize);
	if (nullptr == fileData)
		return;

	IMAGE_EXPORT_DIRECTORY* pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(fileData + pDataDirectory->VirtualAddress - sectionHead->VirtualAddress);
	DWORD funcNumBase = pExportDirectory->Base;
	printf_s("模块名称：%s\n", (const char*)fileData + pExportDirectory->Name - sectionHead->VirtualAddress);
	printf_s("%-35s\t%-10s\t%-10s\n", "导出名", "导出序号", "函数地址");
	for (unsigned i = 0; i < pExportDirectory->NumberOfFunctions; ++i)
	{
		//判断函数地址
		if (0 == *((DWORD*)(fileData + pExportDirectory->AddressOfFunctions - sectionHead->VirtualAddress) + i))
		{
			continue;
		}

		//判断该函数有没有名字
		bool findFuncName = false;
		for (DWORD funcName = 0; funcName < pExportDirectory->NumberOfNames; ++funcName)
		{
			short funcNameOrdinals = *((short*)(fileData + pExportDirectory->AddressOfNameOrdinals - sectionHead->VirtualAddress) + funcName);
			if (funcNameOrdinals == i - pExportDirectory->Base + 1)
			{
				DWORD funcNameOffset = *((DWORD*)(fileData + pExportDirectory->AddressOfNames - sectionHead->VirtualAddress) + funcName);
				printf_s("%-35s\t", (const char*)fileData+ funcNameOffset - sectionHead->VirtualAddress);
				findFuncName = true;
			}
		}

		if(false == findFuncName)
		{
			//无导出函数名
			printf_s("%-35s\t", "null");
		}

		//输出序号
		printf_s("%-10d\t", pExportDirectory->Base + i);

		//函数地址
		printf_s("0x%-08X\n", *((DWORD*)(fileData + pExportDirectory->AddressOfFunctions - sectionHead->VirtualAddress) + i));
	}
}
