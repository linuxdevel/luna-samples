        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                       	 *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************





        OBJECTIVE : 
	- This sample demonstrates how to retrieve a list of all available slots.
	- C_GetSlotList function will be used to retrieve a list of all token present slots.
	- This sample also uses C_GetTokenInfo to retrieve and display information about all detected slots.
*/





#include <stdio.h>
#include <cryptoki_v2.h>
#include <string.h>
#include <stdlib.h>


// Windows and Linux OS uses different header files for loading libraries.
#ifdef OS_UNIX
        #include <dlfcn.h> // For Unix/Linux OS.
#else
        #include <windows.h> // For Windows OS.
#endif


// Windows uses HINSTANCE for storing library handles.
#ifdef OS_UNIX
        void *libHandle = 0; // Library handle for Unix/Linux
#else
        HINSTANCE libHandle = 0; //Library handle for Windows.
#endif


CK_FUNCTION_LIST *p11Func = NULL;
CK_SESSION_HANDLE hSession = 0;
CK_SLOT_ID *slots = NULL; // for storing a list of all token present slot.



// Loads Luna cryptoki library
void loadLunaLibrary()
{
	CK_C_GetFunctionList C_GetFunctionList = NULL;

	char *libPath = getenv("P11_LIB"); // P11_LIB is the complete path of Cryptoki library.
	if(libPath==NULL)
	{
		printf("P11_LIB environment variable not set.\n");
		printf("\n > On Unix/Linux :-\n");
		printf("export P11_LIB=<PATH_TO_CRYPTOKI>");
		printf("\n\n > On Windows :-\n");
		printf("set P11_LIB=<PATH_TO_CRYPTOKI>");
		printf("\n\nExample :-");
		printf("\nexport P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so");
		printf("\nset P11_LIB=C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll\n\n");
		exit(1);
	}


	#ifdef OS_UNIX
		libHandle = dlopen(libPath, RTLD_NOW); // Loads shared library on Unix/Linux.
	#else
		libHandle = LoadLibrary(libPath); // Loads shared library on Windows.
	#endif
	if(!libHandle)
	{
		printf("Failed to load Luna library from path : %s\n", libPath);
		exit(1);
	}


	#ifdef OS_UNIX
	    C_GetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle, "C_GetFunctionList"); // Loads symbols on Unix/Linux
	#else
            C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle, "C_GetFunctionList"); // Loads symbols on Windows.
	#endif

	C_GetFunctionList(&p11Func); // Gets the list of all Pkcs11 Functions.
	if(p11Func==NULL)
	{
		printf("Failed to load P11 functions.\n");
		exit(1);
	}

	printf ("\n> P11 library loaded.\n");
	printf ("  --> %s\n", libPath);
}


// Always a good idea to free up some memory before exiting.
void freeMem()
{
        #ifdef OS_UNIX
                dlclose(libHandle); // Close library handle on Unix/Linux
        #else
                FreeLibrary(libHandle); // Close library handle on Windows.
        #endif
	free(slots);
}



// Checks if a P11 operation was a success or failure
void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		printf("%s failed with Ox%lX\n\n",message,rv);
		p11Func->C_Finalize(NULL_PTR);
		exit(1);
	}
}



int main(int argc, char **argv[])
{
	CK_ULONG detectedSlots = 0;
	loadLunaLibrary();
	checkOperation(p11Func->C_Initialize(NULL_PTR), "C_Initialize"); // Initialize cryptoki.
	
	checkOperation(p11Func->C_GetSlotList(CK_TRUE, NULL_PTR, &detectedSlots), "C_GetSlotList"); // First C_GetSlotList to determine the amount of memory to allocate.
	slots = (CK_SLOT_ID*)calloc(detectedSlots, 1); // allocating memory to slots variable based on the number of detected slots.
	checkOperation(p11Func->C_GetSlotList(CK_TRUE, slots, &detectedSlots), "C_GetSlotList"); // writes a list of slot IDs to slots.
	

	if(detectedSlots==0) 
	{
		printf("No slots were detected.");
		freeMem();
	} 
	else 
	{
		for(int ctr=0;ctr<detectedSlots;ctr++) 
		{
			CK_TOKEN_INFO tokenInfo;
			CK_VERSION firmwareVersion;
			char *slotLabel = NULL;
			char *manufacturer = NULL;
			char *model = NULL;
			char *serialNumber = NULL;

			checkOperation(p11Func->C_GetTokenInfo(slots[ctr], &tokenInfo), "C_GetTokenInfo"); // Retrieves information about the slot.
			
			slotLabel = (char*)calloc(sizeof(tokenInfo.label), 1);
			memcpy(slotLabel, tokenInfo.label, sizeof(tokenInfo.label));
			
			manufacturer = (char*)calloc(sizeof(tokenInfo.label), 1);
			memcpy(manufacturer, tokenInfo.manufacturerID, sizeof(tokenInfo.manufacturerID));
			
			model = (char*)calloc(sizeof(tokenInfo.model), 1);
			memcpy(model, tokenInfo.model, sizeof(tokenInfo.model));

			serialNumber = (char*)calloc(sizeof(tokenInfo.serialNumber), 1);
			memcpy(serialNumber, tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber));

			firmwareVersion = tokenInfo.firmwareVersion;

			printf("\n[ SLOT : %lu ]\n", slots[ctr]);
			printf("  - Label        : %s\n", slotLabel);
			printf("  - Manufacturer : %s\n", manufacturer);
			printf("  - Model        : %s\n", model);
			printf("  - Serial       : %s\n", serialNumber);
			printf("  - Firmware     : %d.%d\n", firmwareVersion.major, firmwareVersion.minor);
			printf("  - Total Memory : %lu.\n", tokenInfo.ulTotalPublicMemory);
			printf("  - Free Memory  : %lu.\n", tokenInfo.ulFreePublicMemory);
			printf("-----------------------------------\n");
		}
	}
	checkOperation(p11Func->C_Finalize(NULL_PTR), "C_Finalize");
	
	freeMem();
	return 0;
}
