//  Hello Kitty Unpacker and Config Extractor 
//  Profero.io ( https://profero.io/)

#include <windows.h>
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>


#define CBC 1

unsigned int MZ_PE_LEN;
unsigned int MZ_BASE;
unsigned int FinalSectionRA;


unsigned short iNumSec = 0;

unsigned int iRelocVaddr = 0;

IMAGE_SECTION_HEADER pTail[10];

IMAGE_DOS_HEADER DosHdr = { 0 };
IMAGE_FILE_HEADER FileHdr = { 0 };
IMAGE_OPTIONAL_HEADER32 OptHdr = { 0 };

unsigned int RelocBlockSize = 0;
unsigned int *FixUp = 0;
unsigned char *pMappedImage = NULL;
unsigned int MZPESize;
unsigned char *MZPEDATA;

char* LoadPEImage(char *fileName);
void SaveFile(unsigned char *buf, unsigned int bufSize, char *Fname);
unsigned char RegEx[] = {
		0x8B, 0x7C, 0x24, 0x04, 0x89, 0x7C, 0x24, 0x5C, 0x8D, 0x35
	};
 
unsigned char KeyPat[27] = {
		0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x50, 0x55, 0x42, 0x4C, 0x49,
		0x43, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D , 0x0a
	};

void readFileBuffer(char *FileName)
{

	unsigned int fSize = 0;
	DWORD dwBytesRead = 0;
	HANDLE hFile;
	hFile = CreateFile(FileName,                // file to open

		GENERIC_READ,          // open for reading

		FILE_SHARE_READ,    // share for reading

		NULL,                  // default security

		OPEN_EXISTING,         // existing file only

		FILE_ATTRIBUTE_NORMAL, // normal file

		NULL);                 // no attr. template

	fSize = GetFileSize(hFile, NULL);

	MZPESize = fSize;
	printf("\"n File Size = %d\n", fSize);
	MZPEDATA = (unsigned char *)malloc(sizeof(char) * fSize);

	if (hFile == INVALID_HANDLE_VALUE)

	{

		printf("\nCant open File\n");
		ExitProcess(-1);
		

	}

	if (ReadFile(hFile, MZPEDATA, (fSize), &dwBytesRead, NULL) == FALSE)

	{


        ExitProcess(-1);
		CloseHandle(hFile);

		return 1;

	}

	CloseHandle(hFile);

	return 0;
}



int main(int argc , char *argv[])
{
        
    char Ivector[17] = {0};
    unsigned int *PXT = NULL;
    const short KeyLen = 16;
    char *EncData = NULL;
    int EncDataLen = 0;
    unsigned int Index = 0;
    unsigned char C2[0x200] =  {0};
    struct AES_ctx ctx;

    

    if ( argc < 4)
    {
        printf("\n Hello Kitty Extractor and Unpacker\
        %s [input] [key] [dump]\n", argv[0]);
        return -1;
    }



    MZPEDATA = LoadPEImage(argv[1]);
    
    for ( int i = 0; i < MZ_PE_LEN; i++)
    {
            if ( !memcmp(MZPEDATA + i, RegEx, sizeof(RegEx)))
            {
                Index = i;
                break;
            }
    }
	printf("Index = %d\n", Index);
    printf("\n[] Extracting IV Offset pointer ....");
    PXT = ( unsigned int *)  (MZPEDATA + Index + sizeof(RegEx));
    
   
    memcpy(Ivector, MZPEDATA  + ( *PXT - MZ_BASE), KeyLen);
	readFileBuffer(argv[1]);

    printf("\n[] Ivector = %s\n", Ivector);

    printf("\n Overlay section RA %x lenth = %d\n", FinalSectionRA, MZPESize - FinalSectionRA);
    
    EncDataLen = (MZPESize - FinalSectionRA);
    EncData = (char* ) malloc(   sizeof(char) * EncDataLen + 1 );

	readFileBuffer(argv[1]);
    
    memset(EncData, 0x01 , EncDataLen);
    memcpy(EncData, FinalSectionRA + MZPEDATA, EncDataLen);

    
    AES_init_ctx_iv(&ctx, argv[2], Ivector);
    AES_CBC_decrypt_buffer(&ctx, EncData, EncDataLen);

    SaveFile(EncData, EncDataLen, argv[3]);
    
	readFileBuffer(argv[3]);


    for ( int i = 0; i < MZPESize; i++)
    {
            if ( !memcmp(MZPEDATA + i, "http://", 7) )
            {
                Index = i;
                printf("\n[] C2 = %s\n", MZPEDATA + i);
                break;
            }
    }
    
    for ( int i = 0; i < MZPESize; i++)
    {
            if ( !memcmp(MZPEDATA + i, KeyPat, sizeof(KeyPat)) )
            {
                Index = i;
                printf("\n[] RSA Key = \n%s\n", MZPEDATA + i );
                break;
            }
    }

    return 0;
}


char* LoadPEImage(char *fileName)

{

    FILE *fp = NULL;
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

	printf("\n Final Section RA = %d", FinalSectionRA);
    fclose(fp);
    return pMappedImage;
}

void SaveFile(unsigned char *DataBuffer, unsigned int dwBytesToWrite, char *FileName)
{
	HANDLE hFile;
	DWORD dwBytesWritten = 0;

	hFile = CreateFile(FileName,
		GENERIC_WRITE,         
		0,                      
		NULL,                  
		CREATE_NEW,             
		FILE_ATTRIBUTE_NORMAL,  
		NULL);                  

	if (hFile == INVALID_HANDLE_VALUE)
	{
		
		printf(" failure: Unable to open file %s", FileName);
		return;
	}


	 WriteFile(
		hFile,           
		DataBuffer,      
		dwBytesToWrite,  
		&dwBytesWritten, 
		NULL);            

	CloseHandle(hFile);
    return;
}
