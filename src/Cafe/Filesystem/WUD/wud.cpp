#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wud.h"
#include "Common/VFSFileStream.h"
#ifdef HAVE_ORE
#include <strings.h>
#include <smelt.h>

// An ORE's own name for its platform, and what it holds: a title lists its
// folder's files, a disc none. libsmelt opens the file by name itself, not
// through the frontend's VFS.
static WiiUOreKind wud_oreKind(smelt_ingot* ingot)
{
	char platform[16];
	size_t platformLen = sizeof(platform);
	size_t fileCount = 0;
	if (smelt_platform(ingot, platform, &platformLen) != SMELT_OK || strcmp(platform, "wiiu") != 0)
		return WiiUOreKind::NOT_ORE;
	if (smelt_file_count(ingot, &fileCount) != SMELT_OK)
		return WiiUOreKind::NOT_ORE;
	return fileCount ? WiiUOreKind::TITLE : WiiUOreKind::DISC;
}

static bool wud_isOreFile(const fs::path& path)
{
	VFSFileStream* fs = VFSFileStream::openFile2(path);
	if (!fs)
		return false;
	char magic[4] = {};
	bool isOre = fs->readData(magic, sizeof(magic)) == sizeof(magic) && memcmp(magic, "ORE1", 4) == 0;
	delete fs;
	return isOre;
}

// A title's id from its TMD, as NUSspli (title.tmd) or the CDN (tmd,
// tmd.<version>) names it: after its RSA-2048 signature, at 0x18C
static bool wud_oreTitleId(smelt_ingot* ingot, unsigned long long* titleIdOut)
{
	size_t count = 0;
	if (smelt_file_count(ingot, &count) != SMELT_OK)
		return false;
	for (size_t i = 0; i < count; i++)
	{
		char name[256];
		size_t nameLen = sizeof(name);
		uint64_t offset = 0, size = 0;
		if (smelt_file_at(ingot, i, name, &nameLen, &offset, &size) != SMELT_OK)
			continue;
		if (strcasecmp(name, "title.tmd") != 0 && strcasecmp(name, "tmd") != 0 && strncasecmp(name, "tmd.", 4) != 0)
			continue;
		uint8_t head[0x194];
		if (size < sizeof(head) || smelt_read(ingot, offset, head, sizeof(head)) != SMELT_OK)
			return false;
		if (head[0] != 0x00 || head[1] != 0x01 || head[2] != 0x00 || head[3] != 0x04)
			return false;
		unsigned long long titleId = 0;
		for (int b = 0; b < 8; b++)
			titleId = (titleId << 8) | head[0x18C + b];
		*titleIdOut = titleId;
		return true;
	}
	return false;
}

WiiUOreKind wud_probeOre(const fs::path& path, unsigned long long* titleIdOut)
{
	if (!wud_isOreFile(path))
		return WiiUOreKind::NOT_ORE;
	smelt_ingot* ingot = nullptr;
	if (smelt_open(_pathToUtf8(path).c_str(), nullptr, &ingot) != SMELT_OK)
	{
		cemuLog_log(LogType::Force, "ORE {}: {}", _pathToUtf8(path), smelt_last_error());
		return WiiUOreKind::NOT_ORE;
	}
	WiiUOreKind kind = wud_oreKind(ingot);
	if (titleIdOut)
	{
		*titleIdOut = 0;
		if (kind == WiiUOreKind::TITLE)
			wud_oreTitleId(ingot, titleIdOut);
	}
	smelt_close(ingot);
	return kind;
}

// a disc ORE as a WUD: its byte view is the disc as dumped
static wud_t* wud_openOre(const fs::path& path)
{
	smelt_ingot* ingot = nullptr;
	if (smelt_open(_pathToUtf8(path).c_str(), nullptr, &ingot) != SMELT_OK)
	{
		cemuLog_log(LogType::Force, "ORE {}: {}", _pathToUtf8(path), smelt_last_error());
		return nullptr;
	}
	uint64_t size = 0;
	if (wud_oreKind(ingot) != WiiUOreKind::DISC || smelt_logical_size(ingot, &size) != SMELT_OK)
	{
		smelt_close(ingot);
		return nullptr;
	}
	wud_t* wud = (wud_t*)malloc(sizeof(wud_t));
	memset(wud, 0x00, sizeof(wud_t));
	wud->ore = ingot;
	wud->uncompressedSize = (long long)size;
	return wud;
}
#endif

wud_t* wud_open(const fs::path& path)
{
#ifdef HAVE_ORE
	if (wud_isOreFile(path))
		return wud_openOre(path);
#endif
	VFSFileStream* fs = VFSFileStream::openFile2(path);
	if( !fs )
		return nullptr;
	// allocate wud struct
	wud_t* wud = (wud_t*)malloc(sizeof(wud_t));
	memset(wud, 0x00, sizeof(wud_t));
	wud->fs = fs;
	// get size of file
	long long inputFileSize = wud->fs->GetSize();
	// determine whether the WUD is compressed or not
	wuxHeader_t wuxHeader = {0};
	if( wud->fs->readData(&wuxHeader, sizeof(wuxHeader_t)) != sizeof(wuxHeader_t))
	{
		// file is too short to be either
		wud_close(wud);
		return nullptr;
	}
	if( wuxHeader.magic0 == WUX_MAGIC_0 && wuxHeader.magic1 == WUX_MAGIC_1 )
	{
		// this is a WUX file
		wud->isCompressed = true;
		wud->sectorSize = wuxHeader.sectorSize;
		wud->uncompressedSize = wuxHeader.uncompressedSize;
		// validate header values
		if( wud->sectorSize < 0x100 || wud->sectorSize >= 0x10000000 )
		{
			wud_close(wud);
			return nullptr;
		}
		// calculate offsets and sizes
		wud->indexTableEntryCount = (unsigned int)((wud->uncompressedSize+(long long)(wud->sectorSize-1)) / (long long)wud->sectorSize);
		wud->offsetIndexTable = sizeof(wuxHeader_t);
		wud->offsetSectorArray = (wud->offsetIndexTable + (long long)wud->indexTableEntryCount*sizeof(unsigned int));
		// align to SECTOR_SIZE
		wud->offsetSectorArray = (wud->offsetSectorArray + (long long)(wud->sectorSize-1));
		wud->offsetSectorArray = wud->offsetSectorArray - (wud->offsetSectorArray%(long long)wud->sectorSize);
		// read index table
		unsigned int indexTableSize = sizeof(unsigned int) * wud->indexTableEntryCount;
		wud->indexTable = (unsigned int*)malloc(indexTableSize);
		wud->fs->SetPosition(wud->offsetIndexTable);
		if( wud->fs->readData(wud->indexTable, indexTableSize) != indexTableSize )
		{
			// could not read index table
			wud_close(wud);
			return nullptr;
		}
	}
	else
	{
		// uncompressed file
		wud->uncompressedSize = inputFileSize;
	}
	return wud;
}

void wud_close(wud_t* wud)
{
#ifdef HAVE_ORE
	smelt_close(wud->ore);
#endif
	delete wud->fs;
	if( wud->indexTable )
		free(wud->indexTable);
	free(wud);
}

bool wud_isWUXCompressed(wud_t* wud)
{
	return wud->isCompressed;
}

/*
 * Read data from WUD file
 * Can read up to 4GB at once
 */
unsigned int wud_readData(wud_t* wud, void* buffer, unsigned int length, long long offset)
{
	// make sure there is no out-of-bounds read
	long long fileBytesLeft = wud->uncompressedSize - offset;
	if( fileBytesLeft <= 0 )
		return 0;
	if( fileBytesLeft < (long long)length )
		length = (unsigned int)fileBytesLeft;
	// read data
	unsigned int readBytes = 0;
#ifdef HAVE_ORE
	if (wud->ore)
	{
		if (smelt_read(wud->ore, (uint64_t)offset, (uint8_t*)buffer, length) != SMELT_OK)
		{
			cemuLog_log(LogType::Force, "ORE read of {} bytes at {:#x}: {}", length, offset, smelt_last_error());
			return 0;
		}
		return length;
	}
#endif
	if( wud->isCompressed == false )
	{
		// uncompressed read is straight forward
		wud->fs->SetPosition(offset);
		readBytes = (unsigned int)wud->fs->readData(buffer, length);
	}
	else
	{
		// compressed read must be handled on a per-sector level
		while( length > 0 )
		{
			unsigned int sectorOffset = (unsigned int)(offset % (long long)wud->sectorSize);
			unsigned int remainingSectorBytes = wud->sectorSize - sectorOffset;
			unsigned int sectorIndex = (unsigned int)(offset / (long long)wud->sectorSize);
			unsigned int bytesToRead = (remainingSectorBytes<length)?remainingSectorBytes:length; // read only up to the end of the current sector
			// look up real sector index
			sectorIndex = wud->indexTable[sectorIndex];
			wud->fs->SetPosition(wud->offsetSectorArray + (long long)sectorIndex * (long long)wud->sectorSize + (long long)sectorOffset);
			readBytes += (unsigned int)wud->fs->readData(buffer, bytesToRead);
			// progress read offset, write pointer and decrease length
			buffer = (void*)((char*)buffer + bytesToRead);
			length -= bytesToRead;
			offset += bytesToRead;

		}
	}
	return readBytes;
}

/*
 * Returns the size of the data
 * For .wud: Size of file
 * For .wux: Size of uncompressed data
 */
long long wud_getWUDSize(wud_t* wud)
{
	return wud->uncompressedSize;
}