#include "ArchiveReader.hpp"
#include <winnt.h>
#include <fstream>
#include <iostream>
#include <iomanip>

using namespace ArReaderClass;

ArReader::ArReadResult ArReader::parse(const void* data, const std::size_t size)
{
	std::uint8_t* p = reinterpret_cast<std::uint8_t*>(const_cast<void*>(data));

	auto nextWordLE = [&p]()
	{
		const auto value = *reinterpret_cast<std::uint16_t*>(p);
		p += sizeof(value);
		return value;
	};

	auto nextDwordLE = [&p]()
	{
		const auto value = *reinterpret_cast<std::uint32_t*>(p);
		p += sizeof(value);
		return value;
	};

	auto nextWordBE = [&p]()
	{
		const auto value = *reinterpret_cast<std::uint16_t*>(&std::vector<std::uint8_t>({ p[1], p[0] })[0]);
		p += sizeof(value);
		return value;
	};

	auto nextDwordBE = [&p]()
	{
		const auto value = *reinterpret_cast<std::uint32_t*>(&std::vector<std::uint8_t>({ p[3], p[2], p[1], p[0] })[0]);
		p += sizeof(value);
		return value;
	};

	auto nextString = [&p](const std::size_t count)
	{
		std::string str = count > 0 ? std::string(reinterpret_cast<char*>(p), count) : std::string(reinterpret_cast<char*>(p));
		p += count > 0 ? count : strlen(str.c_str());
		return str;
	};

	auto nextLinkerHeader = [&p]()
	{
		// Combined field (all the strings combined, read as one)
		std::string headerField(reinterpret_cast<char*>(p), 60);

		// Each of these strings is left justified and padded with trailing spaces within a field of 16 bytes:
		LinkerMember link;

		// Interestingly the offsets vary from the documentation
		// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#archive-member-headers
		// So a check was added for both instances
		// 
		if (strncmp(reinterpret_cast<char*>(p + 58), IMAGE_ARCHIVE_END, strlen(IMAGE_ARCHIVE_END)) == 0)
		{
			link = LinkerMember
			{
				headerField.substr(0, 16),
				headerField.substr(16, 12),
				headerField.substr(28, 6),
				headerField.substr(34, 6),
				headerField.substr(40, 8),
				headerField.substr(48, 10)
			};
			p += 60;
		}
		else if (strncmp(reinterpret_cast<char*>(p + 42), IMAGE_ARCHIVE_END, strlen(IMAGE_ARCHIVE_END)) == 0)
		{
			link = LinkerMember
			{
				headerField.substr(0, 16),
				headerField.substr(16, 8),
				headerField.substr(24, 4),
				headerField.substr(28, 4),
				headerField.substr(32, 8),
				headerField.substr(40, 2)
			};
			p += 44;
		}
		else
		{
			throw std::exception("Invalid end of archive header");
			return link;

		}

		//while (!link.Name.empty() && link.Name.back() == ' ') link.Name.pop_back();
		//while (!link.Date.empty() && link.Date.back() == ' ') link.Date.pop_back();
		//while (!link.UserID.empty() && link.UserID.back() == ' ') link.UserID.pop_back();
		//while (!link.GroupID.empty() && link.GroupID.back() == ' ') link.GroupID.pop_back();
		//while (!link.Mode.empty() && link.Mode.back() == ' ') link.Mode.pop_back();
		//while (!link.Size.empty() && link.Size.back() == ' ') link.Size.pop_back();

		return link;
	};

	Header = std::string(reinterpret_cast<char*>(p), IMAGE_ARCHIVE_START_SIZE);
	p += IMAGE_ARCHIVE_START_SIZE;

	if (Header != IMAGE_ARCHIVE_START)
	{
		throw std::exception("Invalid image archive header");
		return Failed;
	}

	char* header = nullptr;

	//
	// Parse the first two linker members 
	// First one is always present and is just for legacy
	//
	for (std::size_t nLinkerHeader = 1; nLinkerHeader <= 2; nLinkerHeader++)
	{
		header = reinterpret_cast<char*>(p);

		if (strncmp(header, IMAGE_ARCHIVE_LINKER_MEMBER, strlen(IMAGE_ARCHIVE_LINKER_MEMBER)) == 0)
		{
			p += 0x10;

			LinkerMember link = nextLinkerHeader();

			switch (nLinkerHeader)
			{
			case 1:
			{
				link.NumSymbols = nextDwordBE();
				//
				//std::cout << "Number of Symbols: " << link.NumSymbols << std::endl;

				for (std::uint32_t i = 0; i < link.NumSymbols; i++)
				{
					link.Offsets.push_back(nextDwordBE());
					//std::cout << "Offset (" << i << "): " << link.Offsets.back() << std::endl;
				}

				break;
			}
			case 2:
			{
				link.NumMembers = nextDwordLE();
				//std::cout << "Number of Members: " << link.NumMembers << std::endl;

				for (std::uint32_t i = 0; i < link.NumMembers; i++)
				{
					link.Offsets.push_back(nextDwordLE());
					//std::cout << "Offset (" << i << "): " << std::hex << link.Offsets.back() << std::endl;
				}

				link.NumSymbols = nextDwordLE();
				//std::cout << "Number of Symbols: " << link.NumSymbols << std::endl;

				for (std::uint32_t i = 0; i < link.NumSymbols; i++)
				{
					link.Indices.push_back(nextWordLE());
					//std::cout << "Got (" << i << ") index: " << link.Indices.back() << std::endl;
				}

				break;
			}
			}

			for (std::uint32_t i = 0; i < link.NumSymbols; i++)
			{
				std::string str(reinterpret_cast<char*>(p));
				if (!str.empty())
				{
					link.Strings.push_back(str);
					p += str.length() + 1;
					//std::cout << "String (symbol): " << str << std::endl;
				}
			}

			Links.push_back(link);
		}

		while (*p == 0x0A) p++;
	}

	if (Links.empty())
		return Success;

	header = reinterpret_cast<char*>(p);

	//
	// Begin parsing the "LONGNAMES" linker member
	//

	const std::size_t nObjects = Links.back().NumMembers;

	if (strncmp(header, IMAGE_ARCHIVE_LONGNAMES_MEMBER, strlen(IMAGE_ARCHIVE_LONGNAMES_MEMBER)) == 0)
	{
		p += 0x10;

		LinkerMember link = nextLinkerHeader();

		for (std::uint32_t i = 0; i < nObjects; i++)
		{
			std::string str(reinterpret_cast<char*>(p));
			if (!str.empty())
			{
				LongNames.push_back(str);
				p += str.length() + 1;
				//std::cout << "Object name: " << str << std::endl;
			}
		}

		Links.push_back(link);
	}
	else
	{
		throw std::exception("Expected longnames header");
		return Failed;
	}

	/*
	In an import library with the long format, a single member contains the following information:
		- Archive member header
		- File header
		- Section headers
		- Data that corresponds to each of the section headers
		- COFF symbol table
		- Strings
	*/

	//std::cout << "Number of archive objects: " << nObjects << std::endl;

	for (std::uint32_t i = 0; i < nObjects; i++)
	{
		while (*p == 0x0A) p++;

		header = reinterpret_cast<char*>(p);
		if (header[0] != '/')
		{
			throw std::exception("Invalid parsing of header");
			return Failed;
		}

		Links.front().ResolvedOffsets[p - reinterpret_cast<std::uint8_t*>(const_cast<void*>(data))] = i;

		p += 0x10;


		LinkerMember link = nextLinkerHeader();

		// Start of the file header for reference
		//
		auto pFileHeader = p;

		// Parse the File header (COFF Header)
		//
		auto machine = nextWordLE(); // e.g. IMAGE_FILE_MACHINE_AMD64
		auto nSections = nextWordLE();
		auto timeDateStamp = nextDwordLE();
		auto ptrToSymbolTable = nextDwordLE();
		auto nSymbols = nextDwordLE();
		auto sizeOptHeader = nextWordLE();
		auto attributes = nextWordLE();

		//std::cout << "Number of sections: " << nSections << std::endl;

		if (nSections == 0xffff)
			break;

		for (std::size_t nsection = 0; nsection < nSections; nsection++)
		{
			SectionInfo sectionInfo{ 0 };

			std::string sectionName = nextString(0x10);

			while (sectionName.find("$") != std::string::npos)
				sectionName.pop_back();

			//printf("Section name: %s\n", sectionName.c_str());

			strcpy_s(sectionInfo.SectionName, sectionName.c_str());

			sectionInfo.SectionSize = nextDwordLE();
			sectionInfo.SectionOffset = nextDwordLE();
			sectionInfo.SectionPointer = nextDwordLE();

			// Currently unknown, but also unused
			const auto unkValue1 = nextDwordLE();
			const auto unkValue2 = nextDwordLE();
			const auto unkValue3 = nextWordLE();
			const auto unkValue4 = nextWordLE();
			//std::cout << "Unknown value: " << std::hex << unkValue1 << std::endl;
			//std::cout << "Unknown value: " << std::hex << unkValue2 << std::endl;
			//std::cout << "Unknown value: " << std::hex << unkValue3 << std::endl;
			//std::cout << "Unknown value: " << std::hex << unkValue4 << std::endl;

			link.Sections.push_back(sectionInfo);

			//std::cout <<  "Section name: " << sectionInfo.SectionName << "\nOffset: " << std::hex << sectionInfo.SectionOffset << ". Size: " << std::hex << sectionInfo.SectionSize << std::endl;
		}

		// Collect the section datas
		//
		for (auto& section : link.Sections)
		{
			p = pFileHeader + section.SectionOffset;

			if (section.SectionSize > 0) {
				section.Contents.resize(section.SectionSize);
				memcpy(&section.Contents[0], p, section.SectionSize);
			}
			//std::cout << "Section '" << section.SectionName << "' bytes -> ";
			//std::for_each(p, p + 0x14, [](const std::uint8_t c) { //std::cout << std::hex << std::setw(2) << std::setfill('0') << (c & 0xff) << ' '; });
			//std::cout << std::endl;

			p += section.SectionSize;
		}


		struct Relocation
		{
			std::uint32_t CodeOffset;
			std::uint32_t Index;
			std::uint16_t Size;
		};

		std::vector<Relocation> relocations{ };

		// Push back the relocation section which follows code (.text)
		// 
		for (auto sectionIter = link.Sections.begin(); sectionIter != link.Sections.end(); ++sectionIter)
		{
			if (strcmp(sectionIter->SectionName, ".text") == 0 && (sectionIter + 1) != link.Sections.end())
			{
				// Rough size estimate...
				// This is not good, sometimes it can be a negative number
				// if there's no relocation data after .text.

				auto nextSection = sectionIter + 1;

				while (nextSection != link.Sections.end() && nextSection->SectionOffset == NULL)
					nextSection++;

				const std::size_t relocSectionSize = (nextSection->SectionOffset - (sectionIter->SectionOffset + sectionIter->SectionSize));
				
				// Unfortunately, there is nothing I've found that tells us
				// the size of the relocation data, or if it's even there.
				// What we do here is check in-between the end of .text, and the
				// beginning of the next section (usually .data) for any data
				// 
				bool hasRelocations = (relocSectionSize >= 0xA && relocSectionSize < INT_MAX);
				if (hasRelocations)
				{
					SectionInfo sectionInfo{ 0 };

					std::string sectionName = ".reloc";
					strcpy_s(sectionInfo.SectionName, sectionName.c_str());

					sectionInfo.SectionOffset = (sectionIter->SectionOffset + sectionIter->SectionSize);
					sectionInfo.SectionSize = nextSection->SectionOffset - sectionInfo.SectionOffset;
					sectionInfo.SectionPointer = (sectionIter->SectionPointer + sectionIter->SectionSize);

					// Slight adjustment...(padding again??)
					//
					while ((pFileHeader + sectionInfo.SectionOffset)[0] == 0 && sectionInfo.SectionSize > 0)
					{
						sectionInfo.SectionOffset++;
						sectionInfo.SectionSize--;
					}

					sectionInfo.Contents.resize(sectionInfo.SectionSize);
					memcpy(&sectionInfo.Contents[0], pFileHeader + sectionInfo.SectionOffset, sectionInfo.SectionSize);
					//link.Sections.insert(sectionIter + 1, sectionInfo);

					for (std::size_t i = 0; i < sectionInfo.Contents.size(); i += 10)
					{
						relocations.push_back(
							{
								*reinterpret_cast<std::uint32_t*>(&sectionInfo.Contents.at(i)),
								*reinterpret_cast<std::uint32_t*>(&sectionInfo.Contents.at(i + 4)),
								*reinterpret_cast<std::uint16_t*>(&sectionInfo.Contents.at(i + 8))
							}
						);
					}

					
					// We want to put our section at the end so as
					// not to interfere with symbol SectionNumber indices
					link.Sections.emplace_back(sectionInfo);

					nSections++;
				}

				break;
			}
		}

		// Zero padding
		while (*p == NULL) p++;

		// Go through symbols
		for (std::size_t symbolIndex = 0; symbolIndex < nSymbols; symbolIndex++)
		{
			//std::cout << "Symbol [" << symbolIndex << "] bytes -> ";
			//std::for_each(p, p + 0x14, [](const std::uint8_t c){ //std::cout << std::hex << std::setw(2) << std::setfill('0') << (c & 0xff) << ' '; });
			//std::cout << std::endl;

			std::string symbolName = nextString(0x8);

			// The value that is associated with the symbol.
			// The interpretation of this field depends on SectionNumber and StorageClass.
			// A typical meaning is the relocatable address. 
			auto value = nextDwordLE();
			auto value2 = *reinterpret_cast<std::uint32_t*>(&symbolName[4]); // value

			// The signed integer that identifies the section, using a one-based index
			// into the section table. Some values have special meaning
			// FF FF = -1 = IMAGE_SYM_ABSOLUTE // The symbol has an absolute (non-relocatable) value and is not an address. 
			// 00 00 = 0 = IMAGE_SYM_UNDEFINED // The symbol record is not yet assigned a section.
			// A value of zero indicates that a reference to an external symbol is defined elsewhere.
			// A value of non-zero is a common symbol with a size that is specified by the value
			const auto sectionNumber = nextWordLE();

			// Symbol type (0x20 = function, 0x00 = not a function)
			const auto type = nextWordLE();

			// An enumerated value that represents storage class
			// Microsoft tools rely on Visual C++ debug format for most symbolic information
			// and generally use only four storage-class values: EXTERNAL (2), STATIC (3),
			// FUNCTION (101), and FILE (103). 
			const auto storageClass = *p++;

			// The number of auxiliary symbol table entries that follow this record. 
			const auto numberOfAuxSymbols = *p++;

			/*
			if (static_cast<int16_t>(sectionNumber) == IMAGE_SYM_ABSOLUTE)
				//std::cout << "Symbol name (absolute): " << symbolName << std::endl;
			else if (numberOfAuxSymbols >= 1)
				//std::cout << "Symbol name (auxiliary): " << symbolName << std::endl;
			else
				//std::cout << "Symbol value : " << value << std::endl;
			*/

			link.Symbols.push_back(
				{
					symbolName,
					value,
					value2,
					sectionNumber,
					type,
					storageClass,
					numberOfAuxSymbols
				}
			);
		}

		// Not sure why this is length of strings + 5
		// 
		auto sizeStrings = nextDwordLE();
		if (sizeStrings > 5)
			sizeStrings -= 5;

		auto strStart = p;

		// Traverse strings until we reach either the end
		// or the beginning of another archive header
		//
		while (p - strStart < sizeStrings && *p != 0x2F && *p != 0x0A)
		{
			std::string str = nextString(NULL);
			//if (str.empty()) break;
			// 
			//std::cout << "Linker string: " << str << std::endl;
			link.Strings.push_back(str);
			p++;
		}

		//std::cout << "Finished processing header. Remaining bytes: ";
		//std::for_each(p, p + 0x14, [](const std::uint8_t c) { //std::cout << std::hex << std::setw(2) << std::setfill('0') << (c & 0xff) << ' '; });
		//std::cout << std::endl;

		// Go until the next padding (indicates eof)
		// Or to the next header intro.
		// Do not go past the end of file/size
		auto init_pos = reinterpret_cast<std::uint8_t*>(const_cast<void*>(data));
		while (*p != 0x2F && *p != 0x0A && (init_pos - p) < size) p++;

		// Add to the list of ObjectMembers
		// Associated with this Link
		ObjectMembers.push_back(
			{
				link,
				{
					machine,
					nSections,
					timeDateStamp,
					ptrToSymbolTable,
					nSymbols,
					sizeOptHeader,
					attributes
				}
			}
		);
	}

	return Success;
};

ArReader::ArReadResult ArReader::parseFile(const std::filesystem::path libPath)
{
	std::ifstream file(libPath, std::ios::binary | std::ios::ate);

	if (file.fail())
	{
		file.close();
		return Failed;
	}

	const auto fileSize = file.tellg();

	std::vector<std::uint8_t> source(fileSize, 0);
	file.seekg(0, std::ios::beg);
	file.read(reinterpret_cast<char*>(&source[0]), fileSize);
	file.close();

	return parse(source.data(), fileSize);
}
