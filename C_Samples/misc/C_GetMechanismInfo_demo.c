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





        OBJECTIVE : This sample demonstrates how to retrieve information about a mechanism using C_GetMechanismInfo function.
*/





#include <stdio.h>
#include <cryptoki_v2.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

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
CK_SLOT_ID slotId = 0; // slot id

struct mechanismList
{
	CK_ULONG mechCode;
	CK_BYTE *mechString;
}
mechList[] =
{
	{0x00000000, "CKM_RSA_PKCS_KEY_PAIR_GEN"},
	{0x0000000a, "CKM_RSA_X9_31_KEY_PAIR_GEN"},
	{0x00000001, "CKM_RSA_PKCS"},
	{0x00000006, "CKM_SHA1_RSA_PKCS"},
	{0x00000009, "CKM_RSA_PKCS_OAEP"},
	{0x80000142, "CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN"},
	{0x80000143, "CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN"},
	{0x0000000b, "CKM_RSA_X9_31"},
	{0x0000000c, "CKM_SHA1_RSA_X9_31"},
	{0x80000135, "CKM_SHA224_RSA_X9_31"},
	{0x80000136, "CKM_SHA256_RSA_X9_31"},
	{0x80000137, "CKM_SHA384_RSA_X9_31"},
	{0x80000138, "CKM_SHA512_RSA_X9_31"},
	{0x0000000d, "CKM_RSA_PKCS_PSS"},
	{0x0000000e, "CKM_SHA1_RSA_PKCS_PSS"},
	{0x00000010, "CKM_DSA_KEY_PAIR_GEN"},
	{0x00000011, "CKM_DSA"},
	{0x00000012, "CKM_DSA_SHA1"},
	{0x00000046, "CKM_SHA224_RSA_PKCS"},
	{0x00000047, "CKM_SHA224_RSA_PKCS_PSS"},
	{0x00000040, "CKM_SHA256_RSA_PKCS"},
	{0x00000043, "CKM_SHA256_RSA_PKCS_PSS"},
	{0x00000041, "CKM_SHA384_RSA_PKCS"},
	{0x00000044, "CKM_SHA384_RSA_PKCS_PSS"},
	{0x00000042, "CKM_SHA512_RSA_PKCS"},
	{0x00000045, "CKM_SHA512_RSA_PKCS_PSS"},
	{0x00000066, "CKM_SHA3_224_RSA_PKCS"},
	{0x00000067, "CKM_SHA3_224_RSA_PKCS_PSS"},
	{0x00000060, "CKM_SHA3_256_RSA_PKCS"},
	{0x00000063, "CKM_SHA3_256_RSA_PKCS_PSS"},
	{0x00000061, "CKM_SHA3_384_RSA_PKCS"},
	{0x00000064, "CKM_SHA3_384_RSA_PKCS_PSS"},
	{0x00000062, "CKM_SHA3_512_RSA_PKCS"},
	{0x00000065, "CKM_SHA3_512_RSA_PKCS_PSS"},
	{0x00001080, "CKM_AES_KEY_GEN"},
	{0x00001081, "CKM_AES_ECB"},
	{0x00001082, "CKM_AES_CBC"},
	{0x0000108a, "CKM_AES_CMAC"},
	{0x0000108b, "CKM_AES_CMAC_GENERAL"},
	{0x00001085, "CKM_AES_CBC_PAD"},
	{0x00002106, "CKM_AES_CFB8"},
	{0x00002107, "CKM_AES_CFB128"},
	{0x00002104, "CKM_AES_OFB"},
	{0x00001086, "CKM_AES_CTR"},
	{0x80000170, "CKM_AES_KW"},
	{0x80000171, "CKM_AES_KWP"},
	{0x00001087, "CKM_AES_GCM"},
	{0x0000108e, "CKM_AES_GMAC"},
	{0x00000220, "CKM_SHA_1"},
	{0x00000255, "CKM_SHA224"},
	{0x00000256, "CKM_SHA224_HMAC"},
	{0x00000257, "CKM_SHA224_HMAC_GENERAL"},
	{0x00000250, "CKM_SHA256"},
	{0x00000251, "CKM_SHA256_HMAC"},
	{0x00000252, "CKM_SHA256_HMAC_GENERAL"},
	{0x00000260, "CKM_SHA384"},
	{0x00000261, "CKM_SHA384_HMAC"},
	{0x00000262, "CKM_SHA384_HMAC_GENERAL"},
	{0x00000270, "CKM_SHA512"},
	{0x00000271, "CKM_SHA512_HMAC"},
	{0x00000272, "CKM_SHA512_HMAC_GENERAL"},
	{0x000002b5, "CKM_SHA3_224"},
	{0x000002b6, "CKM_SHA3_224_HMAC"},
	{0x000002b7, "CKM_SHA3_224_HMAC_GENERAL"},
	{0x000002b0, "CKM_SHA3_256"},
	{0x000002b1, "CKM_SHA3_256_HMAC"},
	{0x000002b2, "CKM_SHA3_256_HMAC_GENERAL"},
	{0x000002c0, "CKM_SHA3_384"},
	{0x000002c1, "CKM_SHA3_384_HMAC"},
	{0x000002c2, "CKM_SHA3_384_HMAC_GENERAL"},
	{0x000002d0, "CKM_SHA3_512"},
	{0x000002d1, "CKM_SHA3_512_HMAC"},
	{0x000002d2, "CKM_SHA3_512_HMAC_GENERAL"},
	{0x80000f00, "CKM_SHAKE_128"},
	{0x80000f01, "CKM_SHAKE_256"},
	{0x00001040, "CKM_EC_KEY_PAIR_GEN"},
	{0x80000160, "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS"},
	{0x00001041, "CKM_ECDSA"},
	{0x00001042, "CKM_ECDSA_SHA1"},
	{0x00001043, "CKM_ECDSA_SHA224"},
	{0x00001044, "CKM_ECDSA_SHA256"},
	{0x00001045, "CKM_ECDSA_SHA384"},
	{0x00001046, "CKM_ECDSA_SHA512"},
	{0x00001047, "CKM_ECDSA_SHA3_224"},
	{0x00001048, "CKM_ECDSA_SHA3_256"},
	{0x00001049, "CKM_ECDSA_SHA3_384"},
	{0x0000104a, "CKM_ECDSA_SHA3_512"},
	{0x00001050, "CKM_ECDH1_DERIVE"},
	{0x00001051, "CKM_ECDH1_COFACTOR_DERIVE"},
	{0x80000a00, "CKM_ECIES"},
	{0x00001104, "CKM_AES_ECB_ENCRYPT_DATA"},
	{0x00001105, "CKM_AES_CBC_ENCRYPT_DATA"},
	{0x00002000, "CKM_DSA_PARAMETER_GEN"},
	{0x00000030, "CKM_X9_42_DH_KEY_PAIR_GEN"},
	{0x00000031, "CKM_X9_42_DH_DERIVE"},
	{0x00000032, "CKM_X9_42_DH_HYBRID_DERIVE"},
	{0x00000350, "CKM_GENERIC_SECRET_KEY_GEN"},
	{0x00000221, "CKM_SHA_1_HMAC"},
	{0x00000222, "CKM_SHA_1_HMAC_GENERAL"},
	{0x00000013, "CKM_DSA_SHA224"},
	{0x00000014, "CKM_DSA_SHA256"},
	{0x00000018, "CKM_DSA_SHA3_224"},
	{0x00000019, "CKM_DSA_SHA3_256"},
	{0x0000001a, "CKM_DSA_SHA3_384"},
	{0x0000001b, "CKM_DSA_SHA3_512"},
	{0x80000a02, "CKM_NIST_PRF_KDF"},
	{0x00001071, "CKM_AES_XTS"},
	{0x00001056, "CKM_EC_MONTGOMERY_KEY_PAIR_GEN"}
};
int listSize = sizeof(mechList)/sizeof(*mechList);


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



// Connects to a Luna slot (C_Initialize, C_OpenSession, C_Login)
void connectToLunaSlot()
{
	checkOperation(p11Func->C_Initialize(NULL), "C_Initialize");
	printf("\n> Connected to Luna.\n");
	printf("  --> SLOT ID : %ld.\n", slotId);
}



// Disconnects from Luna slot (C_Logout, C_CloseSession and C_Finalize)
void disconnectFromLunaSlot()
{
	checkOperation(p11Func->C_Finalize(NULL), "C_Finalize");
	printf("\n> Disconnected from Luna slot.\n\n");
}



// This function retrieves and displays information about a mechanism.
void getMechanismInfo()
{
	CK_MECHANISM_INFO mechInfo;
	bool flag = true;
	int ctr = 0;
	char mechName[45];
	printf("\n> Enter Mechanism : ");
	scanf("%s", mechName);
	do
	{
		if(strcmp(mechList[ctr].mechString, mechName)==0)
		{
			checkOperation(p11Func->C_GetMechanismInfo(slotId, mechList[ctr].mechCode, &mechInfo), "C_GetMechanismInfo");
			printf("\nMininum Keysize : %lu", mechInfo.ulMinKeySize);
			printf("\nMaximum Keysize : %lu", mechInfo.ulMaxKeySize);
			printf("\nHARDWARE        : %s",((mechInfo.flags & CKF_HW)?"YES":"NO"));
			printf("\n---------------------------");
			printf("\n|  CAN ENCRYPT      | %s |",((mechInfo.flags & CKF_ENCRYPT)?"YES":" NO"));
			printf("\n|  CAN DECRYPT      | %s |",((mechInfo.flags & CKF_DECRYPT)?"YES":" NO"));
			printf("\n|  CAN DIGEST       | %s |",((mechInfo.flags & CKF_DIGEST)?"YES":" NO"));
			printf("\n|  CAN SIGN         | %s |",((mechInfo.flags & CKF_SIGN)?"YES":" NO"));
			printf("\n|  SIGN_RECOVER     | %s |",((mechInfo.flags & CKF_SIGN_RECOVER)?"YES":" NO"));
			printf("\n|  CAN VERIFY       | %s |",((mechInfo.flags & CKF_VERIFY)?"YES":" NO"));
			printf("\n|  VERIFY_RECOVER   | %s |",((mechInfo.flags & CKF_VERIFY_RECOVER)?"YES":" NO"));
			printf("\n|  GENERATE KEY     | %s |",((mechInfo.flags & CKF_GENERATE)?"YES":" NO"));
			printf("\n|  GENERATE KEYPAIR | %s |",((mechInfo.flags & CKF_GENERATE_KEY_PAIR)?"YES":" NO"));
			printf("\n|  CAN WRAP         | %s |",((mechInfo.flags & CKF_WRAP)?"YES":" NO"));
			printf("\n|  CAN UNWRAP       | %s |",((mechInfo.flags & CKF_UNWRAP)?"YES":" NO"));
			printf("\n|  CAN DERIVE       | %s |",((mechInfo.flags & CKF_DERIVE)?"YES":" NO"));
			printf("\n---------------------------\n");
			flag=false;
		}
		ctr++;
	}while(flag && ctr<listSize);
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
	connectToLunaSlot();
	getMechanismInfo();
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
