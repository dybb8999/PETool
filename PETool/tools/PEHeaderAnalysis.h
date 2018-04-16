#pragma once
#include <Windows.h>

class CPEHeaderAnalysis : public CTemplateSingle<CPEHeaderAnalysis>
{
public:
	CPEHeaderAnalysis();
	~CPEHeaderAnalysis();

	const IMAGE_DOS_HEADER*			GetIMAGE_DOS_HEADER() const;
	const IMAGE_NT_HEADERS32*		GetIMAGE_NT_HEADERS32() const;
	const IMAGE_NT_HEADERS64*		GetIMAGE_NT_HEADERS64() const;
	const IMAGE_SECTION_HEADER*		GetIMAGE_SECTION_HEADER() const;

	const bool LoadFile(const char *filePath);
	const bool LoadFile(const wchar_t *filePath);
	const bool Analysis();
	const bool isX64() const;
	const WORD GetSectionNum() const;
	const wchar_t* GetFile() const;
	const unsigned char* GetFileData(DWORD startAddress, DWORD& size);
	void RemoveFileData(const unsigned char* data);
	//sconst unsigned char* GetFileData(DWORD )
private:
	bool OpenFile();
	bool ReadDosHeader();
	bool ReadNtHeader();
	bool ReadSectionsHeader();
	void CleanMemory();
private:
	wchar_t m_filePath[1024];
	HANDLE m_hFile;

	IMAGE_DOS_HEADER m_DosHeader;
	IMAGE_NT_HEADERS32 m_NtHeader32;
	IMAGE_NT_HEADERS64 m_NtHeader64;
	IMAGE_SECTION_HEADER *m_pSectionsHeader;

	bool m_IsX64;
};

