#include "stdafx.h"
#include "PEHeaderAnalysis.h"


CPEHeaderAnalysis::CPEHeaderAnalysis()
{
	m_hFile = nullptr;
	m_pSectionsHeader = nullptr;
	m_IsX64 = false;

	memset(m_filePath, 0, sizeof(m_filePath));
}

CPEHeaderAnalysis::~CPEHeaderAnalysis()
{
	if ((NULL == m_hFile) || (INVALID_HANDLE_VALUE == m_hFile))
	{
		return;
	}

	CloseHandle(m_hFile);
	m_hFile = NULL;

	if (NULL != m_pSectionsHeader)
		delete[]m_pSectionsHeader;

	//delete this;
}


const IMAGE_DOS_HEADER* CPEHeaderAnalysis::GetIMAGE_DOS_HEADER() const
{
	return &m_DosHeader;
}

const IMAGE_NT_HEADERS32* CPEHeaderAnalysis::GetIMAGE_NT_HEADERS32() const
{
	return &m_NtHeader32;
}

const IMAGE_NT_HEADERS64* CPEHeaderAnalysis::GetIMAGE_NT_HEADERS64() const
{
	return &m_NtHeader64;
}

const IMAGE_SECTION_HEADER* CPEHeaderAnalysis::GetIMAGE_SECTION_HEADER() const
{
	return m_pSectionsHeader;
}

const bool CPEHeaderAnalysis::LoadFile(const char * filePath)
{
	if (NULL == filePath)
		return false;

	TCHAR buff[1024];
	wsprintf(buff, TEXT("%S"), filePath);
	return LoadFile(buff);
}

const bool CPEHeaderAnalysis::LoadFile(const wchar_t * filePath)
{
	if (NULL == filePath)
		return false;

	CleanMemory();

	wcscpy_s(m_filePath, filePath);
	return OpenFile();
}

const bool CPEHeaderAnalysis::Analysis()
{
	if ((NULL == m_hFile) || (INVALID_HANDLE_VALUE == m_hFile))
	{
		return false;
	}

	if (!ReadDosHeader())
	{
		return false;
	}

	if (!ReadNtHeader())
	{
		return false;
	}

	if (!ReadSectionsHeader())
	{
		return false;
	}
	return true;
}

const bool CPEHeaderAnalysis::isX64() const
{
	return m_IsX64;
}

const WORD CPEHeaderAnalysis::GetSectionNum() const
{
	if (m_IsX64 == true)
	{
		return m_NtHeader64.FileHeader.NumberOfSections;
	}
	else
	{
		return m_NtHeader32.FileHeader.NumberOfSections;
	}
}

const wchar_t* CPEHeaderAnalysis::GetFile() const
{
	return m_filePath;
}

const unsigned char* CPEHeaderAnalysis::GetFileData(DWORD startAddress, DWORD& size)
{
	if (nullptr == m_hFile)
	{
		return nullptr;
	}

	SetFilePointer(m_hFile, startAddress, nullptr, FILE_BEGIN);

	unsigned char *buff = new unsigned char[size];
	if (nullptr == buff)
	{
		return nullptr;
	}

	if (!ReadFile(m_hFile, buff, size, &size, 0))
	{
		delete[]buff;
		return nullptr;
	}

	return buff;
}

void CPEHeaderAnalysis::RemoveFileData(const unsigned char* data)
{
	if (nullptr != data)
	{
		delete[]data;
	}
}

bool CPEHeaderAnalysis::OpenFile()
{
	m_hFile = CreateFile(m_filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (INVALID_HANDLE_VALUE == m_hFile)
	{
		return false;
	}

	return true;
}

bool CPEHeaderAnalysis::ReadDosHeader()
{
	DWORD realSize;

	if (!ReadFile(m_hFile, &m_DosHeader, sizeof(m_DosHeader), &realSize, 0))
	{
		return false;
	}

	if (m_DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}
	return true;
}

bool CPEHeaderAnalysis::ReadNtHeader()
{
	DWORD realSize;
	LONG newPoint = 0;
	SetFilePointer(m_hFile, m_DosHeader.e_lfanew, &newPoint, FILE_BEGIN);
	if (!ReadFile(m_hFile, &m_NtHeader32, sizeof(m_NtHeader32), &realSize, 0))
	{
		return false;
	}

	if (m_NtHeader32.Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	if ((m_NtHeader32.FileHeader.Machine &IMAGE_FILE_MACHINE_AMD64) == IMAGE_FILE_MACHINE_AMD64)
	{
		m_IsX64 = true;
		SetFilePointer(m_hFile, m_DosHeader.e_lfanew, &newPoint, FILE_BEGIN);
		if (!ReadFile(m_hFile, &m_NtHeader64, sizeof(m_NtHeader64), &realSize, 0))
		{
			return false;
		}
	}

	return true;
}

bool CPEHeaderAnalysis::ReadSectionsHeader()
{
	DWORD realSize;
	if (NULL != m_pSectionsHeader)
		delete[]m_pSectionsHeader;

	WORD NumberOfSections = 0;
	if (m_IsX64 == true)
	{
		NumberOfSections = m_NtHeader64.FileHeader.NumberOfSections;
	}
	else
	{
		NumberOfSections = m_NtHeader32.FileHeader.NumberOfSections;
	}

	m_pSectionsHeader = new IMAGE_SECTION_HEADER[NumberOfSections];
	if (!ReadFile(m_hFile, m_pSectionsHeader, sizeof(IMAGE_SECTION_HEADER) * NumberOfSections, &realSize, 0))
	{
		return false;
	}
	return true;
}

void CPEHeaderAnalysis::CleanMemory()
{
	if (nullptr != m_pSectionsHeader)
	{
		delete[]m_pSectionsHeader;
		m_pSectionsHeader = nullptr;
	}

	if (nullptr != m_hFile)
	{
		CloseHandle(m_hFile);
		m_hFile = nullptr;
	}
}
