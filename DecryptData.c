/* 
   (C) Profero.io 
   Hello Kitty Unpacker and Config Extractor 

   This program is free software : you can redistribute it and / or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
   GNU General Public License for more details.
   You should have received a copy of the GNU General Public License
   along with this program.If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "aes.h"

#define WORD short 
#define BYTE  char
#define DWORD unsigned int


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16


typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic; /* 00: MZ Header signature */
    WORD e_cblp; /* 02: Bytes on last page of file */
    WORD e_cp; /* 04: Pages in file */
    WORD e_crlc; /* 06: Relocations */
    WORD e_cparhdr; /* 08: Size of header in paragraphs */
    WORD e_minalloc; /* 0a: Minimum extra paragraphs needed */
    WORD e_maxalloc; /* 0c: Maximum extra paragraphs needed */
    WORD e_ss; /* 0e: Initial (relative) SS value */
    WORD e_sp; /* 10: Initial SP value */
    WORD e_csum; /* 12: Checksum */
    WORD e_ip; /* 14: Initial IP value */
    WORD e_cs; /* 16: Initial (relative) CS value */
    WORD e_lfarlc; /* 18: File address of relocation table */
    WORD e_ovno; /* 1a: Overlay number */
    WORD e_res[4]; /* 1c: Reserved words */
    WORD e_oemid; /* 24: OEM identifier (for e_oeminfo) */
    WORD e_oeminfo; /* 26: OEM information; e_oemid specific */
    WORD e_res2[10]; /* 28: Reserved words */
    DWORD e_lfanew; /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;


typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;



typedef struct _IMAGE_OPTIONAL_HEADER {
    /* Standard fields */
    WORD Magic; /* 0x10b or 0x107 */ /* 0x00 */
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint; /* 0x10 */
    DWORD BaseOfCode;
    DWORD BaseOfData;
    /* NT additional fields */
    DWORD ImageBase;
    DWORD SectionAlignment; /* 0x20 */
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion; /* 0x30 */
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum; /* 0x40 */
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve; /* 0x50 */
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; /* 0x60 */
    /* 0xE0 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

unsigned int MZ_PE_LEN;
DWORD MZ_BASE;
DWORD FinalSectionRA;

char* PreloadPEImage(char *fileName)
{
    unsigned short iNumSec = 0;
    FILE *fp = NULL;
    unsigned int iRelocVaddr = 0;

    IMAGE_SECTION_HEADER pTail[10];

    IMAGE_DOS_HEADER DosHdr = { 0 };
    IMAGE_FILE_HEADER FileHdr = { 0 };
    IMAGE_OPTIONAL_HEADER32 OptHdr = { 0 };
    unsigned int RelocBlockSize = 0;
    unsigned int *FixUp = 0;
    unsigned char *pMappedImage = NULL;

    int i = 0;
    unsigned short  iHdrLen = 0;
    unsigned int delta = 0;

    fp = fopen((const char*)fileName, "rb");
    fread(&DosHdr, sizeof(IMAGE_DOS_HEADER), 0x01, fp);

    fseek(fp, (unsigned int)DosHdr.e_lfanew + 4, SEEK_SET);

    fread(&FileHdr, sizeof(IMAGE_FILE_HEADER), 1, fp);
    fread(&OptHdr, sizeof(IMAGE_OPTIONAL_HEADER32), 1, fp);

    MZ_BASE = OptHdr.ImageBase;


    while (iNumSec < FileHdr.NumberOfSections)
    {
        fread(&pTail[iNumSec], sizeof(IMAGE_SECTION_HEADER), 1, fp);
        iNumSec++;
    }

    MZ_PE_LEN = ftell(fp);
    iHdrLen = MZ_PE_LEN;

    while (i < iNumSec)
    {

        printf("\n name of section =%s , VSize of section  = %d", pTail[i].Name, pTail[i].Misc.VirtualSize);

        MZ_PE_LEN += pTail[i].VirtualAddress;
        FinalSectionRA  = pTail[i].PointerToRawData + pTail[i].SizeOfRawData;
        i++;
    }

    i = 0;
    pMappedImage = (unsigned char*) malloc(sizeof(char)  * MZ_PE_LEN + 10);

    fseek(fp, 0, SEEK_SET);

    fread(pMappedImage, iHdrLen, 0x01, fp);

    i = 0;
    while (i < iNumSec)
    {
        fseek(fp, pTail[i].PointerToRawData, SEEK_SET);

        fread(&pMappedImage[pTail[i].VirtualAddress], pTail[i].SizeOfRawData, 0x01, fp);

        i++;
    }
    fclose(fp);
    return pMappedImage;
}

char *fileData;
unsigned int fileSize;

void readFile(unsigned char *fName)
{
    FILE *fp = fopen(fName, "rb");
    unsigned int fSize = 0;
    if ( fp == NULL)
    {
        printf("Cant open file ... %s", fName);
        exit(-1);
    }

    fseek(fp, 0L, SEEK_END);
    fSize = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    fileSize = fSize;

    fileData = ( unsigned char *) malloc(sizeof(char) * fSize);
    fread(fileData, 0x01, fSize, fp);
    fclose(fp);
    return;

}
void printUsage(char *progName)
{
    printf("\t(C) Profero.io \t\nHello Kitty Extractor and Unpacker\t\nUsage : %s <input_file> <key> <output_file>\n", progName);
}
void DumpMemory(unsigned char *mem, unsigned int memSize)
{
    int i = 0;
    printf("\n");
    for ( i ; i < memSize; i++)
    {
        printf("%.2x ", mem[i]);
        if ( (i % 10 == 0 ) && i != 0)   printf("\n");
    }
    printf("\n");
}

void DumpSave(unsigned char *mem, unsigned int memSize, char *fileName)

{
    FILE *fp = fopen(fileName, "wb");
    fwrite(mem, 0x01, memSize, fp);
    fclose(fp);
    return;
}

#define CBC 1

int main(int argc , char **argv)
{

    unsigned char pattern[] =
    {
        0x8B, 0x7C, 0x24, 0x04, 0x89, 0x7C, 0x24, 0x5C, 0x8D, 0x35
    };

    unsigned char KeyPat[27] = {
        0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x50, 0x55, 0x42, 0x4C, 0x49,
        0x43, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D , 0x0a
    };

    unsigned int Index = 0;
    char IV[17] = {0};
    unsigned int *IV_PTR = NULL;
    const short KeyLen = 16;
    char *EncData = NULL;
    int EncDataLen = 0;
    unsigned char C2[0x200] =  {0};
    struct AES_ctx ctx;


    if ( argc < 4)
    {
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }
    readFile(argv[1]);

    fileData = PreloadPEImage(argv[1]);

    for ( int i = 0; i < MZ_PE_LEN; i++)
    {
        if ( !memcmp(fileData + i, pattern, sizeof(pattern)))
        {
            Index = i;
            break;
        }
    }

    printf("\n[] Extracting IV Offset pointer ....");
    IV_PTR = ( unsigned int *)  (fileData + Index + sizeof(pattern));
    DumpMemory(IV_PTR, 4);

    memcpy(IV, fileData  + ( *IV_PTR - MZ_BASE), KeyLen);

    printf("\n[] IV = %s\n", IV);
    DumpMemory(IV, KeyLen);

    printf("\n Overlay section RA %x lenth = %d\n", FinalSectionRA, fileSize - FinalSectionRA);

    EncDataLen = (fileSize - FinalSectionRA);
    EncData = (char* ) malloc(   sizeof(char) * EncDataLen + 1 );

    readFile(argv[1]);

    memset(EncData, 0x01 , EncDataLen);
    memcpy(EncData, FinalSectionRA + fileData, EncDataLen);


    AES_init_ctx_iv(&ctx, argv[2], IV);
    AES_CBC_decrypt_buffer(&ctx, EncData, EncDataLen);

    DumpSave(EncData, EncDataLen, argv[3]);

    readFile(argv[3]);


    for ( int i = 0; i < fileSize; i++)
    {
        if ( !memcmp(fileData + i, "http://", 7) )
        {
            Index = i;
            printf("\n[] C2 = %s\n", fileData + i);
            break;
        }
    }

    for ( int i = 0; i < fileSize; i++)
    {
        if ( !memcmp(fileData + i, KeyPat, sizeof(KeyPat)) )
        {
            Index = i;
            printf("\n[] RSA Key = \n%s\n", fileData + i );
            break;
        }
    }

    return 0;
}
