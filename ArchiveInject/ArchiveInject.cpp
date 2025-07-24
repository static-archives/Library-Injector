#include "ArchiveInject.hpp"
#include <Windows.h>
#include <iostream>
#include <format>

using namespace ArReaderClass;
using namespace ArInjectClass;

Export ArInject::getExport(const std::string& name)
{
	for (auto iter = exports.begin(); iter != exports.end(); iter++)
		if (iter->ExportName == name)
			return *iter;

	return {};
}

struct FunctionWriteData
{
	std::string name;
	std::uintptr_t address;
	std::uint8_t* source;
	std::size_t size;
	std::unordered_map<std::uintptr_t, std::pair<int32_t, std::size_t>>functionLinks;
};

ArInject::ArInjectResult ArInject::inject(
	std::vector<std::pair<std::uintptr_t, std::uintptr_t>> codeLocations, 
	std::vector<std::pair<std::uintptr_t, std::uintptr_t>> dataLocations, 
	std::vector<std::pair<std::uintptr_t, std::uintptr_t>> rdataLocations, 
	const ArReader& reader, 
	std::unordered_map<std::string, std::uintptr_t> relocateSymbols
){
	std::size_t dataCaveIndex = 0;
	std::size_t rdataCaveIndex = 0;
	std::size_t codeCaveIndex = 0;
	std::uintptr_t codeStart = *reinterpret_cast<const std::uintptr_t*>(&codeLocations[codeCaveIndex].first);
	std::uintptr_t dataStart = *reinterpret_cast<const std::uintptr_t*>(&dataLocations[dataCaveIndex].first);
	std::uintptr_t rdataStart = *reinterpret_cast<const std::uintptr_t*>(&rdataLocations[rdataCaveIndex].first);
	std::uintptr_t codePos = codeStart;
	std::uintptr_t dataPos = dataStart;
	std::uintptr_t rdataPos = rdataStart;

	std::vector<FunctionWriteData> functionWriteData(reader.ObjectMembers.size());
	std::vector<std::uintptr_t> functionAddresses{ };
	std::unordered_map<std::string, std::uintptr_t>functionMap = {};
	std::unordered_map<std::uintptr_t, std::pair<std::int32_t, std::size_t>> functionLinks{ };
	std::unordered_map<std::string, std::pair<std::uintptr_t, std::size_t>> functionNameLinks{ };
	std::vector<std::uint8_t> code{ }, initData{ };

	exports.clear();



	std::uintptr_t dataPreStart = dataStart;
	//std::cout << "Writing pre symbol data from " << std::hex << dataPos;

	for (auto& iter : relocateSymbols)
	{
		std::vector<std::uint8_t> bytes(sizeof(std::uintptr_t), 0);
		memcpy(&bytes[0], &iter.second, sizeof(std::uintptr_t));
		initData.insert(end(initData), begin(bytes), end(bytes));
		iter.second = dataPos;
		dataPos += sizeof(std::uintptr_t);
	}

	// Code alignment
	for (std::size_t i = 0; i < 1 + (dataPos % 8); i++)
	{
		initData.push_back(0);
		dataPos++;
	}
	//std::cout << " to " << std::hex << dataPos << std::endl;

	std::uint32_t skipped = 0, symbolIndex = 0;



	for (auto obj = reader.ObjectMembers.begin(); obj != reader.ObjectMembers.end(); ++obj)
	{
		const auto memberIndex = obj - reader.ObjectMembers.begin();

		functionWriteData[memberIndex].functionLinks = {};

		// Calculate whether there's enough room for this function
		//
		std::vector<std::uint8_t> preRData = {};
		std::vector<std::uint8_t> preCode = {};
		std::size_t preRDataSize = 0;
		std::size_t preCodeSize = 0;
		std::size_t padding = 0;

		for (const auto section : obj->Link.Sections)
		{
			if (strcmp(section.SectionName, ".text") == 0)
			{
				preCodeSize = section.Contents.size();
				preCode = section.Contents;
				break;
			}
			else
			{
				// Not only should the code section fit within these bounds
				// but also other necessary sections...This could be optimized
				// but now its every other section in this object member
				padding += section.Contents.size();
			}
		}

		for (const auto section : obj->Link.Sections)
		{
			if (strcmp(section.SectionName, ".rdata") == 0)
			{
				preRDataSize = section.Contents.size();
				preRData = section.Contents;
				//padding += section.Contents.size();
				break;
			}
		}

		if (preCodeSize != 0)
		{
			std::uintptr_t codeEnd = *reinterpret_cast<std::uintptr_t*>(&codeLocations[codeCaveIndex].second);

			if (codePos > codeEnd || codePos + preCodeSize + padding > codeEnd)
			{
				++codeCaveIndex;
				if (codeCaveIndex >= codeLocations.size())
				{
					//printf("0x%016xb needed for code inject\n", codePos - codeEnd);
					
					throw std::exception("Not enough page memory for code");
					return Failed;
				}
				else
				{
					auto old = codeStart;
					codeStart = *reinterpret_cast<std::uintptr_t*>(&codeLocations[codeCaveIndex].first);
					
					codePos = codeStart;
				}
			}


			int extSymbols = 0;
			auto offsets = reader.Links.front().Offsets;
			auto symbolIndexStart = symbolIndex;
			while (1)
			{
				functionAddresses.push_back(codePos);
				//printf("String %s mapped to %p (%02X, %p)\n", reader.Links[0].Strings[symbolIndex].c_str(), reader.Links[1].Indices[symbolIndex], offsets[symbolIndex], codePos);

				bool found = false;

				for (auto exp : exports)
				{
					if (exp.ExportName == reader.Links[0].Strings[symbolIndex])
					{
						found = true;
						break;
					}
				}

				if (!found)
				{
					Export exp;
					exp.Address = codePos;
					exp.ExportName = reader.Links[0].Strings[symbolIndex];
					exports.push_back(exp);
				}

				++symbolIndex;

				if (symbolIndex >= offsets.size())
					break;

				if (offsets[symbolIndex] != offsets[symbolIndexStart])
					break;

				extSymbols++;
			}
		}
		else
		{
			//printf("No code section");
		}

		// Not used rn, used to keep track of mapped strings
		//functionMap[reader.Links[0].Strings[symbolIndexStart]] = codePos;

		std::unordered_map<std::int32_t, std::pair<std::int32_t, std::string>> stringIndexMap{ };

		// Look up the RAW string offset , translate it to 
		// an index
		//
		for (std::size_t i = 0, at = 4; i < obj->Link.Strings.size(); i++)
		{
			std::string str = obj->Link.Strings[i];
			//printf("String %s ID = %02X. Position: %i\n", str.c_str(), i, at);
			stringIndexMap[at] = { i, str };
			at += str.length() + 1;
		}

		struct Relocation
		{
			std::uint32_t CodeOffset;
			std::uint32_t Index;
			std::uint16_t Size;
		};

		std::vector<Relocation> relocations{ };
		std::unordered_map<std::string, std::pair<std::uintptr_t, std::vector<std::uint8_t>>>sectionMap;

		sectionMap[".text"] = { codePos, {} };
		sectionMap[".rdata"] = { rdataPos, {} };
		sectionMap[".data"] = { };
		sectionMap[".bss"] = { };
		sectionMap[".reloc"] = { };

		// Gather the necessary sections
		//
		for (const auto section : obj->Link.Sections)
			if (sectionMap.find(std::string(section.SectionName)) != sectionMap.end())
				sectionMap[std::string(section.SectionName)].second = section.Contents;

		// Write rdata (readonly data) at the entries provided
		//
		if (preRDataSize)
		{
			std::uintptr_t rdataEnd = *reinterpret_cast<const std::uintptr_t*>(&rdataLocations[rdataCaveIndex].second);
			if (rdataPos + preRDataSize >= rdataEnd)
			{
				printf("%pb needed for rdata inject", rdataPos - rdataEnd);
				throw std::exception("Not enough page memory for rdata");
				return Failed;
			}

			//std::cout << "Writing section data for .rdata from " << std::hex << rdataPos;

			auto dataBytes = &sectionMap[".rdata"].second;
			if (!dataBytes->empty())
			{
				rdataPos += dataBytes->size();

				// Data alignment (8 bytes)
				for (std::size_t i = 0; i < 1 + (rdataPos % 8); i++)
				{
					dataBytes->push_back(0);
					rdataPos++; // align
				}

				WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(sectionMap[".rdata"].first), dataBytes->data(), dataBytes->size(), nullptr);
			}

			//std::cout << " to " << std::hex << rdataPos << std::endl;

			rdataPos += 0x10;
		}

		auto codeBytes = &sectionMap[".text"].second;
		if (!codeBytes->empty())
		{
			auto relocBytes = &sectionMap[".reloc"].second;
			if (!relocBytes->empty())
			{
				for (std::size_t i = 0; i < relocBytes->size(); i += 10)
				{
					relocations.push_back(
						{
							*reinterpret_cast<std::uint32_t*>(&relocBytes->at(i)),
							*reinterpret_cast<std::uint32_t*>(&relocBytes->at(i + 4)),
							*reinterpret_cast<std::uint16_t*>(&relocBytes->at(i + 8))
						}
					);
				}
			}

			//std::cout << "Writing string data from " << std::hex << dataPos;
			std::uintptr_t stringsStart = dataPos;
			std::vector<std::uintptr_t> stringTableLocs{ };
			std::vector<std::uint8_t> stringBuffer{ };

			for (const auto& str : obj->Link.Strings)
			{
				stringTableLocs.push_back(dataPos);

				for (std::size_t i = 0; i < str.length() + 1; i++)
				{
					stringBuffer.push_back(str[i]);
					dataPos++;
				}
			}
			//std::cout << " to " << std::hex << dataPos << std::endl;

			WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(stringsStart), stringBuffer.data(), stringBuffer.size(), nullptr);

			for (auto& sectionName : std::vector<std::string>({ ".data", /*".rdata",*/ ".bss" }))
			{
				std::uintptr_t dataEnd = *reinterpret_cast<std::uintptr_t*>(&dataLocations[dataCaveIndex].second);
				std::uintptr_t dataSize = sectionMap[sectionName].second.size();

				if (dataPos + dataSize > dataEnd)
				{
					++dataCaveIndex;
					if (dataCaveIndex >= dataLocations.size())
					{
						printf("%pb needed for %s inject", dataPos - dataEnd, sectionName.c_str());
						throw std::exception("Not enough page memory for data");
						return Failed;
					}
					else
					{
						auto old = dataStart;
						dataStart = *reinterpret_cast<std::uintptr_t*>(&dataLocations[dataCaveIndex].first);
						dataPos = dataStart;
					}
				}

				//std::cout << "Writing section data for " << sectionName << " from " << std::hex << dataPos;

				sectionMap[sectionName].first = dataPos;

				auto dataBytes = &sectionMap[sectionName].second;
				if (!dataBytes->empty())
				{
					dataPos += dataBytes->size();

					if (strcmp(sectionName.c_str(), ".bss") == 0)
					{
						memset(dataBytes->data(), NULL, dataBytes->size());
					}

					// Data alignment (8 bytes)
					for (std::size_t i = 0; i < 1 + (dataPos % 8); i++)
					{
						dataBytes->push_back(0);
						dataPos++; // align
					}

					WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(sectionMap[sectionName].first), dataBytes->data(), dataBytes->size(), nullptr);
				}

				//std::cout << " to " << std::hex << dataPos << std::endl;
			}


			std::unordered_map<std::size_t, std::uintptr_t> symbolMap = {};
			std::unordered_map<std::size_t, std::size_t> symbolSizeMap = {};

			// Place for empty values; uninitialized variables
			if (!obj->Link.Symbols.empty())
			{
				std::vector<std::uint8_t> symbolDataBytes = {};
				std::uintptr_t symbolsPos = dataPos;

				//std::cout << "Writing symbol data from " << std::hex << dataPos;

				for (std::size_t i = 0; i < obj->Link.Symbols.size(); i++)
				{
					std::string symbolName;

					auto symbol = obj->Link.Symbols[i];
					switch (symbol.StorageClass)
					{
					case IMAGE_SYM_CLASS_EXTERNAL:
					{
						// Non-function extern values are defined by the symbol
						// basically.
						switch (symbol.Type)
						{
						case 0:
						{
							// A value of non-zero is a common symbol with a size that is specified by the value
							// 
							if (symbol.SectionNumber > 0 && static_cast<std::int16_t>(symbol.SectionNumber) != IMAGE_SYM_ABSOLUTE)
							{
								auto valueSize = symbol.Value2;
								if (valueSize <= 4)
								{
									// Symbol defines the value, because the value is <= 4 bytes
									//printf("Symbol %i definition. Value: %p\n", i, symbol.Value);

									symbolMap[i] = dataPos;
									symbolSizeMap[i] = valueSize;

									std::vector<std::uint8_t> valueBytes(valueSize, 0);
									if (valueSize > 0) {
										memcpy(&valueBytes[0], &symbol.Value, valueSize);
									}

									for (auto b : valueBytes)
										symbolDataBytes.push_back(b);

									// Data alignment (8 bytes)
									for (std::size_t l = 0; l < 1 + (dataPos % 8); l++)
									{
										symbolDataBytes.push_back(0);
										dataPos++; // align
									}
								}
							}
							break;
						}
						}
						break;
					}
					}

				}

				//std::cout << " to " << hex << dataPos << std::endl;

				if (!symbolDataBytes.empty())
					WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(symbolsPos), symbolDataBytes.data(), symbolDataBytes.size(), nullptr);
			}

			// Iterate relocations, check type of relocation
			// and take user input into consideration
			// 
			for (const auto& reloc : relocations)
			{
				auto symbol = obj->Link.Symbols[reloc.Index];

				std::string symbolName;

				switch (symbol.StorageClass)
				{
				case IMAGE_SYM_CLASS_STATIC:
				{
					
					std::uintptr_t dataLoc = sectionMap[std::string(obj->Link.Sections[symbol.SectionNumber - 1].SectionName)].first + symbol.Value;
					const auto newOffset = dataLoc - (codePos + reloc.CodeOffset + reloc.Size);
					memcpy(codeBytes->data() + reloc.CodeOffset, &newOffset, reloc.Size);

					//printf("Static Type (%02X) -->  '%s'(%i). SectionNumber: %p. Code offset: %p. Now pointing to: %p\n", symbol.Type, symbolName.c_str(), symbolName.length(), symbol.SectionNumber, codePos + reloc.CodeOffset, codePos + newOffset);
					//printf("Section location: %p. Symbol value: %p. Reloc size: %p\n", sectionMap[std::string(obj->Link.Sections[symbol.SectionNumber - 1].SectionName)].first, symbol.Value, reloc.Size);

					break;
				}
				case IMAGE_SYM_CLASS_EXTERNAL:
				{
					if (symbol.Name[0] != 0)
					{
						int i = 0;
						while (symbol.Name[i] >= 0x20 && symbol.Name[i] < 0x7F && i < 8)
							symbolName += symbol.Name[i++];
					}
					else
						symbolName = stringIndexMap[symbol.Value2].second;

					//printf("External Type (%02X) --> '%s'(%i). SectionNumber: %p. Code offset: %p\n", symbol.Type, symbolName.c_str(), symbolName.length(), symbol.SectionNumber, codePos + reloc.CodeOffset);

					if (relocateSymbols.find(symbolName) != relocateSymbols.end())
					{
						const auto ptr = *reinterpret_cast<std::uintptr_t*>(&relocateSymbols[symbolName]);
						const auto newOffset = ptr - (codePos + reloc.CodeOffset + reloc.Size);
						memcpy(codeBytes->data() + reloc.CodeOffset, &newOffset, reloc.Size);
					}
					else
					{
						// Check if symbol type is a function (w/ another archive member)
						//
						switch (symbol.Type)
						{
						case 0x20:
						{
							// This needs to be linked at the end, once we finished the code array
							// 
							std::uint32_t functionId = 0;

							if (symbol.Value && symbolName[0] == '?')
							{
								const auto newOffset = symbol.Value - (reloc.CodeOffset + reloc.Size);
								memcpy(codeBytes->data() + reloc.CodeOffset, &newOffset, reloc.Size);
							}
							else
							{
								// Translate the symbol name to the index of the function in order,
								// store it and then translate it at the very end to the address 
								// we mapped the function to.
								for (auto sIter = reader.Links.front().Strings.begin(); sIter != reader.Links.front().Strings.end(); ++sIter)
								{
									std::string str1(*sIter + ' ');
									std::string str2(symbolName + ' ');

									if (strncmp(str1.c_str(), str2.c_str(), str2.length()) == 0)
									{
										// Look up the real ordered index for the extern symbol
										functionId = sIter - reader.Links.front().Strings.begin();

										const auto initOffset = (codePos - codeStart);
										//functionLinks[initOffset + reloc.CodeOffset] = { functionId, reloc.Size };
										functionWriteData[memberIndex].functionLinks[reloc.CodeOffset] = { functionId, reloc.Size };
										functionId = UINT_MAX;

										break;
									}
								}

								if (functionId != UINT_MAX)
								{
									//printf("Could not resolve symbol. Name: %s\n", symbolName.c_str());
								}
							}

							break;
						}
						case 0:
						{
							if (symbol.SectionNumber > 0 && static_cast<std::int16_t>(symbol.SectionNumber) != IMAGE_SYM_ABSOLUTE)
							{
								if (symbol.Value2 <= 4)
								{
									std::uintptr_t dataLoc = symbolMap[reloc.Index - 1];
									const auto newOffset = dataLoc - (codePos + reloc.CodeOffset + reloc.Size);
									memcpy(codeBytes->data() + reloc.CodeOffset, &newOffset, symbolSizeMap[reloc.Index - 1]);
								}
								else
								{
									//printf("SECTION FOR SYMBOL: %s. %p, %p, %p.\n", std::string(obj->Link.Sections[symbol.SectionNumber - 1].SectionName).c_str(), reloc.Index, symbol.Value, symbol.Value2);
									std::uintptr_t dataLoc = sectionMap[std::string(obj->Link.Sections[symbol.SectionNumber - 1].SectionName)].first + symbol.Value;
									const auto newOffset = dataLoc - (codePos + reloc.CodeOffset + reloc.Size);
									memcpy(codeBytes->data() + reloc.CodeOffset, &newOffset, reloc.Size);
								}
							}
							else // if (symbol.SectionNumber == IMAGE_SYM_UNDEFINED)
							{
								//printf("Function ID: %p\n", reader.Links[0].Offsets[symbol.Value2]);
								//printf("%s\n", symbolName.c_str());
								//
								//const auto initOffset = (codePos - codeStart);
								//functionNameLinks[symbolName] = { initOffset + reloc.CodeOffset, reloc.Size };
								
								std::uint32_t functionId = 0;

								for (auto sIter = reader.Links.front().Strings.begin(); sIter != reader.Links.front().Strings.end(); ++sIter)
								{
									std::string str1(*sIter + ' ');
									std::string str2(symbolName + ' ');

									if (strncmp(str1.c_str(), str2.c_str(), str2.length()) == 0)
									{
										// Look up the real ordered index for the extern symbol

										functionId = (sIter - reader.Links.front().Strings.begin());
										//printf("Function ID: %p\n", functionId);
										
										const auto initOffset = (codePos - codeStart);

										//functionLinks[initOffset + reloc.CodeOffset] = { functionId, reloc.Size };
										functionWriteData[memberIndex].functionLinks[reloc.CodeOffset] = { functionId, reloc.Size };

										functionId = UINT_MAX;

										break;
									}
								}
								
								if (functionId != UINT_MAX)
								{
									//printf("Could not resolve symbol. Name: %s\n", symbolName.c_str());
								}
							}

							break;
						}
						}
					}
					break;
				}
				}
			}

			for (std::size_t i = 0; i < (codeBytes->size() % 0x10); i++)
				codeBytes->push_back(0xCC);

			code.insert(end(code), begin(*codeBytes), end(*codeBytes));
			//codePos += codeBytes->size(); // #######

			// Store code information for this function
			auto codeMem = new std::uint8_t[codeBytes->size()];
			memcpy(codeMem, codeBytes->data(), codeBytes->size());
			functionWriteData[memberIndex].address = codePos;
			functionWriteData[memberIndex].source = codeMem;
			functionWriteData[memberIndex].size = codeBytes->size();

			code.empty();

			codePos += codeBytes->size();
		}
		else
		{
			// No sections to inject!
		}
	}

	for (const auto& writeData : functionWriteData)
	{
		if (writeData.size != 0)
		{
			//printf("Writing function from %p to %p\n", writeData.address, writeData.address + writeData.size);
			
			// Configure relative instruction offsets
			for (auto& link : writeData.functionLinks)
			{
				const auto functionId = link.second.first;
				const auto codeOffset = writeData.address + link.first + link.second.second;
				const auto rel = static_cast<std::int32_t>(functionAddresses[functionId] - codeOffset);
				memcpy(writeData.source + link.first, &rel, link.second.second);
			}

			// Write all code at once
			std::size_t nbytes;
			WriteProcessMemory(hProcess, reinterpret_cast<LPVOID*>(writeData.address), writeData.source, writeData.size, &nbytes);
		}

		if (writeData.source)
			delete[] writeData.source;
	}


	if (!initData.empty())
	{
		WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(dataPreStart), initData.data(), initData.size(), nullptr);
	}

	return Success;
}

