        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************





        OBJECTIVE :
	- This sample demonstrates how to view partition policies for a slot.
	- This sample makes use of SFNTExtension function (VENDOR DEFINED FUNCTIONS).
	- SFNTExtensions are supported only by Luna HSMs.
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


CK_FUNCTION_LIST *p11Func = NULL; // Stores all pkcs11 functions.
CK_SFNT_CA_FUNCTION_LIST *sfntFunc = NULL; // Stores all sfnt functions.

CK_SLOT_ID slotId = 0; // slot id
CK_ULONG *capabilities = NULL; // stores the list of capabilities.
CK_ULONG *capabilities_value = NULL; // stores the value of all capabilities.
CK_ULONG capIdSize = 0; // stores the size of capabilities list.
CK_ULONG capValSize = 0; // stores the size of capabilities value list.

CK_ULONG *policies = NULL; // stores the list of all policies.
CK_ULONG *policies_value = NULL; // stores the values for all policies.
CK_ULONG polIdSize = 0; // stores the size of policies list.
CK_ULONG polValSize = 0; // stores the size fo policies value list.


// Loads Luna cryptoki library
void loadLunaLibrary()
{
	CK_C_GetFunctionList C_GetFunctionList = NULL;
	CK_CA_GetFunctionList CA_GetFunctionList = NULL;

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

	// Loads PKCS#11 functions.
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

	// Loads SFNTExtensions.
	#ifdef OS_UNIX
            CA_GetFunctionList = (CK_CA_GetFunctionList)dlsym(libHandle, "CA_GetFunctionList"); // Loads symbols on Unix/Linux
        #else
            CA_GetFunctionList = (CK_CA_GetFunctionList)GetProcAddress(libHandle, "CA_GetFunctionList"); // Loads symbols on Windows.
        #endif

	CA_GetFunctionList(&sfntFunc);
	if(sfntFunc==NULL)
	{
		printf("Failed to load SFNT functions.\n");
		exit(1);
	}
	printf("\n> SafeNet Extensions loaded.\n");
}



// Always a good idea to free up some memory before exiting.
void freeMem()
{
        #ifdef OS_UNIX
                dlclose(libHandle); // Close library handle on Unix/Linux
        #else
                FreeLibrary(libHandle); // Close library handle on Windows.
        #endif
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



// This function enumerates the capabilities of a partition.
void getTokenCapabilities()
{
	checkOperation(sfntFunc->CA_GetTokenCapabilities(slotId, NULL, &capIdSize, NULL, &capValSize), "CA_GetTokenCapabilities");
	capabilities = (CK_ULONG*)calloc(capIdSize, sizeof(CK_ULONG));
	capabilities_value = (CK_ULONG*)calloc(capValSize, sizeof(CK_ULONG));
	checkOperation(sfntFunc->CA_GetTokenCapabilities(slotId, capabilities, &capIdSize, capabilities_value, &capValSize), "CA_GetTokenCapabilities");
}



// This function displays the enumerated capabilities of a slot.
void displayTokenCapabilities()
{
	CK_ULONG elementBitLen;
	CK_ULONG elementDestructive;
	CK_ULONG elementWriteRestricted;
	CK_CHAR *description = NULL;
	CK_ULONG descLen = 0;
	printf("\n\nCapabilities of slot %lu are as follows :-\n", slotId);
	printf("ID\tDescription\n");
	printf("--\t-----------\n");
	for(int ctr=0;ctr<capIdSize;ctr++)
	{
		checkOperation(sfntFunc->CA_GetConfigurationElementDescription(slotId, 1, 1, capabilities[ctr], &elementBitLen, &elementDestructive, &elementWriteRestricted, NULL, &descLen),"CA_GetConfigurationElementDescription");
		description = (CK_CHAR*)calloc(descLen, sizeof(CK_CHAR));
		checkOperation(sfntFunc->CA_GetConfigurationElementDescription(slotId, 1, 1, capabilities[ctr], &elementBitLen, &elementDestructive, &elementWriteRestricted, description, &descLen),"CA_GetConfigurationElementDescription");
		printf("%lu\t%s ==> %lu.\n", capabilities[ctr], description, capabilities_value[ctr]);
		free(description);
	}
}



// This function enumerates the policies of a partition.
void getTokenPolicies()
{
	checkOperation(sfntFunc->CA_GetTokenPolicies(slotId, NULL, &polIdSize, NULL, &polValSize), "CA_GetTokenPolicies");
	policies = (CK_ULONG*)calloc(polIdSize, sizeof(CK_ULONG));
	policies_value = (CK_ULONG*)calloc(polValSize, sizeof(CK_ULONG));
	checkOperation(sfntFunc->CA_GetTokenPolicies(slotId, policies, &polIdSize, policies_value, &polValSize), "CA_GetTokenPolicies");
}



// This function displays all token policies of a partition.
void displayTokenPolicies()
{
	CK_ULONG elementBitLen;
	CK_ULONG elementDestructive;
	CK_ULONG elementWriteRestricted;
	CK_CHAR *description = NULL;
	CK_ULONG descLen = 0;
	printf("\n\nPolicies of slot %lu are as follows :-\n", slotId);
	printf("ID\tDescription\n");
	printf("--\t-----------\n");
	for(int ctr=0;ctr<polIdSize;ctr++)
	{
		checkOperation(sfntFunc->CA_GetConfigurationElementDescription(slotId, 1, 0, policies[ctr], &elementBitLen, &elementDestructive, &elementWriteRestricted, NULL, &descLen),"CA_GetConfigurationElementDescription");
		description = (CK_CHAR*)calloc(descLen, sizeof(CK_ULONG));
		checkOperation(sfntFunc->CA_GetConfigurationElementDescription(slotId, 1, 0, capabilities[ctr], &elementBitLen, &elementDestructive, &elementWriteRestricted, description, &descLen),"CA_GetConfigurationElementDescription");
		printf("%lu\t%s ==> %lu.\n",policies[ctr], description, policies_value[ctr]);
		free(description);
	}
}



// Prints the syntax for executing this code.
void usage(const char exeName[30])
{
	printf("\nUsage :-\n");
	printf("%s <slot_number>\n\n", exeName);
}



int main(int argc, char **argv[])
{
	printf("\n%s\n", (char*)argv[0]);
	if(argc<2) {
		usage((char*)argv[0]);
		exit(1);
	}
	slotId = atoi((const char*)argv[1]);

	loadLunaLibrary();

	checkOperation(p11Func->C_Initialize(NULL), "C_Initialize");
	printf("\n> Connected to slot %lu.\n", slotId);

	getTokenCapabilities();
	printf("\n> Token Capabilities read.\n");

	getTokenPolicies();
	printf("\n> Token Policies read.\n");

	displayTokenCapabilities();
	displayTokenPolicies();

	checkOperation(p11Func->C_Finalize(NULL), "C_Finalize");
	printf("\n> Disconnected from slot %lu.\n\n", slotId);

	freeMem();
	return 0;
}
