#pragma once
#include "ArchiveInject.hpp"
#include <filesystem>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

// Template class
// 
namespace ArInjectClass
{
	typedef class ArInject;
};

// Depended header files:
// - winnt.h
namespace ArReaderClass
{
	// The first 8 bytes of an archive consist of the file signature
	// The rest of the archive consists of a series of archive members, as follows:
	// 
	//		The 1st and 2nd members are "linker members."
	//			Each of these members has its own format as described in section Import Name Type.
	//			Typically, a linker places information into these archive members.
	//			The linker members contain the directory of the archive
	// 
	//		The 3rd member is the "longnames".
	//			This optional member consists of a series of null-terminated ASCII strings
	//			in which each string is the name of another archive member
	//
	//		The rest of the archive consists of standard (object-file) members.
	//			Each of these members contains the contents of one object file
	//			in its entirety.
	//

	typedef std::vector<std::string> LongNames;

	struct SectionInfo
	{
		char SectionName[0x10];
		std::uint32_t SectionSize;
		std::uint32_t SectionOffset;
		std::uint32_t SectionPointer;
		std::vector<std::uint8_t> Contents;
	};

	struct Symbol
	{
		std::string Name;
		std::uint32_t Value, Value2;
		std::uint16_t SectionNumber;
		std::uint16_t Type;
		std::uint8_t StorageClass;
		std::uint8_t NumAuxSymbols;
	};

	struct LinkerMember
	{
		std::string Name;
		std::string Date;
		std::string UserID;
		std::string GroupID;
		std::string Mode;
		std::string Size;
		std::uint32_t NumSymbols;
		std::vector<std::uint32_t> Offsets;
		std::unordered_map<std::int32_t, std::int32_t>ResolvedOffsets;
		std::uint32_t NumMembers;
		std::vector<std::uint16_t> Indices;
		std::vector<std::string> Strings;
		std::vector<Symbol> Symbols;
		std::vector<SectionInfo> Sections;
	};

	struct FileHeader
	{
		std::uint16_t Machine;
		std::uint16_t NumSections;
		std::uint32_t TimeDateStamp;
		std::uint32_t PointerToSymbols;
		std::uint32_t NumSymbols;
		std::uint16_t SizeOptHeader;
		std::uint16_t Attributes;
	};

	struct ObjectFileMember
	{
		LinkerMember Link;
		FileHeader CoffFileHeader;
	};

	class ArReader
	{
	private:
		std::string Header;
		LongNames LongNames;
		std::vector<ObjectFileMember> ObjectMembers;
		std::vector<LinkerMember> Links;

		friend ArInjectClass::ArInject;
	public:
		ArReader() {};
		~ArReader() {};

		/// <summary>
		/// Throws: std::exception for file parse errors.
		/// Returns: enum ArReadResult --> Success(0), or Failed(1)
		/// </summary>
		enum ArReadResult
		{
			Success,
			Failed
		}
		parse(const void* data, const std::size_t size);

		ArReadResult parseFile(const std::filesystem::path libPath);
	};
};
