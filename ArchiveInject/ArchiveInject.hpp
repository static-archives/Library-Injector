#pragma once
#include "ArchiveReader.hpp"
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>

// Template class
// 
namespace ArReaderClass
{
	typedef class ArReader;
};

// Depends on ArReaderClass
//
namespace ArInjectClass
{
	struct Export
	{
		std::string ExportName;
		std::uintptr_t Address;
	};

	class ArInject
	{
	private:
		HANDLE hProcess;
		std::vector<Export> exports;
	public:
		ArInject() { hProcess = GetCurrentProcess(); }
		ArInject(const HANDLE _hProcess) { hProcess = _hProcess; }
		~ArInject() {};

		Export getExport(const std::string& name);

		enum ArInjectResult
		{
			Success,
			Failed
		}
		inject(
			std::vector<std::pair<std::uintptr_t, std::uintptr_t>> codeLocations,
			std::vector<std::pair<std::uintptr_t, std::uintptr_t>> dataLocations,
			std::vector<std::pair<std::uintptr_t, std::uintptr_t>> rdataLocations,
			const ArReaderClass::ArReader& reader,
			std::unordered_map<std::string, std::uintptr_t> relocateSymbols
		);
	};
};
