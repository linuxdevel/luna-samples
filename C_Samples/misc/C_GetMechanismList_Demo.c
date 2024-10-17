        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "Luna-samples" project.                               *
        *                                                                                *
        * The " luna-samples" project is provided under the MIT license (see the         *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************





        OBJECTIVE : This sample displays the list of all mechanisms enabled/supported by the firmware.
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
CK_SLOT_ID slotId = 0; // slot id



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



void displayMechanismName(unsigned int mech)
{
	const char *mechString;
	switch(mech)
	{
        	case CKM_RSA_PKCS_KEY_PAIR_GEN : mechString ="CKM_RSA_PKCS_KEY_PAIR_GEN";
	        break;
	        case CKM_RSA_PKCS : mechString ="CKM_RSA_PKCS";
        	break;
	        case CKM_RSA_9796 : mechString ="CKM_RSA_9796";
        	break;
	        case CKM_RSA_X_509 : mechString ="CKM_RSA_X_509";
        	break;
	        case CKM_MD2_RSA_PKCS : mechString ="CKM_MD2_RSA_PKCS";
        	break;
	        case CKM_MD5_RSA_PKCS : mechString ="CKM_MD5_RSA_PKCS";
        	break;
	        case CKM_SHA1_RSA_PKCS : mechString ="CKM_SHA1_RSA_PKCS";
        	break;
	        case CKM_RIPEMD128_RSA_PKCS : mechString ="CKM_RIPEMD128_RSA_PKCS";
        	break;
	        case CKM_RIPEMD160_RSA_PKCS : mechString ="CKM_RIPEMD160_RSA_PKCS";
        	break;
	        case CKM_RSA_PKCS_OAEP : mechString ="CKM_RSA_PKCS_OAEP";
        	break;
	        case CKM_RSA_X9_31_KEY_PAIR_GEN : mechString ="CKM_RSA_X9_31_KEY_PAIR_GEN";
        	break;
	        case CKM_RSA_X9_31 : mechString ="CKM_RSA_X9_31";
        	break;
        	case CKM_SHA1_RSA_X9_31 : mechString ="CKM_SHA1_RSA_X9_31";
	        break;
        	case CKM_RSA_PKCS_PSS : mechString ="CKM_RSA_PKCS_PSS";
	        break;
	        case CKM_SHA1_RSA_PKCS_PSS : mechString ="CKM_SHA1_RSA_PKCS_PSS";
        	break;
	        case CKM_DSA_KEY_PAIR_GEN : mechString ="CKM_DSA_KEY_PAIR_GEN";
	        break;
        	case CKM_DSA : mechString ="CKM_DSA";
	        break;
	        case CKM_DSA_SHA1 : mechString ="CKM_DSA_SHA1";
        	break;
	        case CKM_DH_PKCS_KEY_PAIR_GEN : mechString ="CKM_DH_PKCS_KEY_PAIR_GEN";
        	break;
	        case CKM_DH_PKCS_DERIVE : mechString ="CKM_DH_PKCS_DERIVE";
        	break;
	        case CKM_X9_42_DH_KEY_PAIR_GEN : mechString ="CKM_X9_42_DH_KEY_PAIR_GEN";
        	break;
	        case CKM_X9_42_DH_DERIVE : mechString ="CKM_X9_42_DH_DERIVE";
        	break;
	        case CKM_X9_42_DH_HYBRID_DERIVE : mechString ="CKM_X9_42_DH_HYBRID_DERIVE";
        	break;
	        case CKM_X9_42_MQV_DERIVE : mechString ="CKM_X9_42_MQV_DERIVE";
        	break;
        	case CKM_SHA224_RSA_PKCS : mechString = "CKM_SHA224_RSA_PKCS";
	        break;
	        case CKM_SHA224_RSA_PKCS_PSS : mechString = "CKM_SHA224_RSA_PKCS_PSS";
        	break;
	        case CKM_SHA256_RSA_PKCS : mechString ="CKM_SHA256_RSA_PKCS";
        	break;
	        case CKM_SHA384_RSA_PKCS : mechString = "CKM_SHA384_RSA_PKCS";
        	break;
	        case CKM_DES3_CMAC : mechString = "CKM_DES3_CMAC";
        	break;
        	case CKM_ARIA_KEY_GEN : mechString = "CKM_ARIA_KEY_GEN";
	        break;
	        case CKM_ARIA_ECB : mechString = "CKM_ARIA_ECB";
        	break;
	        case CKM_ARIA_CBC : mechString = "CKM_ARIA_CBC";
        	break;
	        case CKM_ARIA_CBC_PAD : mechString = "CKM_ARIA_CBC_PAD";
        	break;
	        case CKM_ARIA_MAC : mechString = "CKM_ARIA_MAC";
        	break;
	        case CKM_ARIA_MAC_GENERAL : mechString = "CKM_ARIA_MAC_GENERAL";
        	break;
	        case CKM_SHA224_KEY_DERIVATION : mechString = "CKM_SHA224_KEY_DERIVATION";
        	break;
	        case CKM_SHA512_RSA_PKCS : mechString ="CKM_SHA512_RSA_PKCS";
        	break;
	        case CKM_AES_CMAC : mechString = "CKM_AES_CMAC";
        	break;
	        case CKM_AES_CTR : mechString = "CKM_AES_CTR";
        	break;
	        case CKM_AES_GCM : mechString = "CKM_AES_GCM";
        	break;
	        case CKM_SHA224 : mechString = "CKM_SHA224";
        	break;
	        case CKM_SHA224_HMAC : mechString = "CKM_SHA224_HMAC";
        	break;
	        case CKM_SHA224_HMAC_GENERAL : mechString = "CKM_SHA224_HMAC_GENERAL";
        	break;
	        case CKM_ARIA_ECB_ENCRYPT_DATA : mechString = "CKM_ARIA_ECB_ENCRYPT_DATA";
        	break;
	        case CKM_ARIA_CBC_ENCRYPT_DATA : mechString = "CKM_ARIA_CBC_ENCRYPT_DATA";
        	break;
	        case CKM_SHA256_RSA_PKCS_PSS : mechString ="CKM_SHA256_RSA_PKCS_PSS";
        	break;
	        case CKM_SHA384_RSA_PKCS_PSS : mechString ="CKM_SHA384_RSA_PKCS_PSS";
        	break;
	        case CKM_SHA512_RSA_PKCS_PSS : mechString ="CKM_SHA512_RSA_PKCS_PSS";
        	break;
	        case CKM_RC2_KEY_GEN : mechString ="CKM_RC2_KEY_GEN";
        	break;
	        case CKM_RC2_ECB : mechString ="CKM_RC2_ECB";
        	break;
	        case CKM_RC2_CBC : mechString ="CKM_RC2_CBC";
        	break;
	        case CKM_RC2_MAC : mechString ="CKM_RC2_MAC";
        	break;
	        case CKM_RC2_MAC_GENERAL : mechString ="CKM_RC2_MAC_GENERAL";
	        break;
        	case CKM_RC2_CBC_PAD : mechString ="CKM_RC2_CBC_PAD";
	        break;
        	case CKM_RC4_KEY_GEN : mechString ="CKM_RC4_KEY_GEN";
	        break;
        	case CKM_RC4 : mechString ="CKM_RC4";
	        break;
        	case CKM_DES_KEY_GEN : mechString ="CKM_DES_KEY_GEN";
	        break;
        	case CKM_DES_ECB : mechString ="CKM_DES_ECB";
	        break;
        	case CKM_DES_CBC : mechString ="CKM_DES_CBC";
	        break;
        	case CKM_DES_MAC : mechString ="CKM_DES_MAC";
	        break;
        	case CKM_DES_MAC_GENERAL : mechString ="CKM_DES_MAC_GENERAL";
	        break;
        	case CKM_DES_CBC_PAD : mechString ="CKM_DES_CBC_PAD";
	        break;
        	case CKM_DES2_KEY_GEN : mechString ="CKM_DES2_KEY_GEN";
	        break;
        	case CKM_DES3_KEY_GEN : mechString ="CKM_DES3_KEY_GEN";
	        break;
        	case CKM_DES3_ECB : mechString ="CKM_DES3_ECB";
	        break;
        	case CKM_DES3_CBC : mechString ="CKM_DES3_CBC";
	        break;
        	case CKM_DES3_MAC : mechString ="CKM_DES3_MAC";
	        break;
        	case CKM_DES3_MAC_GENERAL : mechString ="CKM_DES3_MAC_GENERAL";
	        break;
        	case CKM_DES3_CBC_PAD : mechString ="CKM_DES3_CBC_PAD";
	        break;
        	case CKM_CDMF_KEY_GEN : mechString ="CKM_CDMF_KEY_GEN";
	        break;
        	case CKM_CDMF_ECB : mechString ="CKM_CDMF_ECB";
	        break;
        	case CKM_CDMF_CBC : mechString ="CKM_CDMF_CBC";
	        break;
        	case CKM_CDMF_MAC : mechString ="CKM_CDMF_MAC";
	        break;
        	case CKM_CDMF_MAC_GENERAL : mechString ="CKM_CDMF_MAC_GENERAL";
	        break;
        	case CKM_CDMF_CBC_PAD : mechString ="CKM_CDMF_CBC_PAD";
	        break;
        	case CKM_DES_OFB64 : mechString ="CKM_DES_OFB64";
	        break;
        	case CKM_DES_OFB8 : mechString ="CKM_DES_OFB8";
	        break;
        	case CKM_DES_CFB64 : mechString ="CKM_DES_CFB64";
	        break;
        	case CKM_DES_CFB8 : mechString ="CKM_DES_CFB8";
	        break;
        	case CKM_MD2 : mechString ="CKM_MD2";
	        break;
        	case CKM_MD2_HMAC : mechString ="CKM_MD2_HMAC";
	        break;
        	case CKM_MD2_HMAC_GENERAL : mechString ="CKM_MD2_HMAC_GENERAL";
	        break;
        	case CKM_MD5 : mechString ="CKM_MD5";
	        break;
        	case CKM_MD5_HMAC : mechString ="CKM_MD5_HMAC";
	        break;
        	case CKM_MD5_HMAC_GENERAL : mechString ="CKM_MD5_HMAC_GENERAL";
	        break;
        	case CKM_SHA_1 : mechString ="CKM_SHA_1";
	        break;
        	case CKM_SHA_1_HMAC : mechString ="CKM_SHA_1_HMAC";
	        break;
        	case CKM_SHA_1_HMAC_GENERAL : mechString ="CKM_SHA_1_HMAC_GENERAL";
	        break;
        	case CKM_RIPEMD128 : mechString ="CKM_RIPEMD128";
	        break;
        	case CKM_RIPEMD128_HMAC : mechString ="CKM_RIPEMD128_HMAC";
	        break;
        	case CKM_RIPEMD128_HMAC_GENERAL : mechString ="CKM_RIPEMD128_HMAC_GENERAL";
	        break;
        	case CKM_RIPEMD160 : mechString ="CKM_RIPEMD160";
	        break;
        	case CKM_RIPEMD160_HMAC : mechString ="CKM_RIPEMD160_HMAC";
	        break;
        	case CKM_RIPEMD160_HMAC_GENERAL : mechString ="CKM_RIPEMD160_HMAC_GENERAL";
	        break;
        	case CKM_SHA256 : mechString ="CKM_SHA256";
	        break;
        	case CKM_SHA256_HMAC : mechString ="CKM_SHA256_HMAC";
	        break;
        	case CKM_SHA256_HMAC_GENERAL : mechString ="CKM_SHA256_HMAC_GENERAL";
	        break;
        	case CKM_SHA384 : mechString ="CKM_SHA384";
	        break;
        	case CKM_SHA384_HMAC : mechString ="CKM_SHA384_HMAC";
	        break;
        	case CKM_SHA384_HMAC_GENERAL : mechString ="CKM_SHA384_HMAC_GENERAL";
	        break;
        	case CKM_SHA512 : mechString ="CKM_SHA512";
	        break;
        	case CKM_SHA512_HMAC : mechString ="CKM_SHA512_HMAC";
	        break;
        	case CKM_SHA512_HMAC_GENERAL : mechString ="CKM_SHA512_HMAC_GENERAL";
	        break;
        	case CKM_CAST_KEY_GEN : mechString ="CKM_CAST_KEY_GEN";
	        break;
        	case CKM_CAST_ECB : mechString ="CKM_CAST_ECB";
	        break;
        	case CKM_CAST_CBC : mechString ="CKM_CAST_CBC";
	        break;
        	case CKM_CAST_MAC : mechString ="CKM_CAST_MAC";
	        break;
        	case CKM_CAST_MAC_GENERAL : mechString ="CKM_CAST_MAC_GENERAL";
	        break;
        	case CKM_CAST_CBC_PAD : mechString ="CKM_CAST_CBC_PAD";
	        break;
        	case CKM_CAST3_KEY_GEN : mechString ="CKM_CAST3_KEY_GEN";
	        break;
        	case CKM_CAST3_ECB : mechString ="CKM_CAST3_ECB";
	        break;
        	case CKM_CAST3_CBC : mechString ="CKM_CAST3_CBC";
	        break;
        	case CKM_CAST3_MAC : mechString ="CKM_CAST3_MAC";
	        break;
        	case CKM_CAST3_MAC_GENERAL : mechString ="CKM_CAST3_MAC_GENERAL";
	        break;
        	case CKM_CAST3_CBC_PAD : mechString ="CKM_CAST3_CBC_PAD";
	        break;
        	case CKM_CAST5_KEY_GEN : mechString ="CKM_CAST5_KEY_GEN";
	        break;
        	case CKM_CAST5_ECB : mechString ="CKM_CAST5_ECB";
	        break;
        	case CKM_CAST5_CBC : mechString ="CKM_CAST5_CBC";
	        break;
        	case CKM_CAST5_MAC : mechString ="CKM_CAST5_MAC";
	        break;
        	case CKM_CAST5_MAC_GENERAL : mechString ="CKM_CAST5_MAC_GENERAL";
	        break;
        	case CKM_CAST5_CBC_PAD : mechString ="CKM_CAST5_CBC_PAD";
	        break;
        	case CKM_RC5_KEY_GEN : mechString ="CKM_RC5_KEY_GEN";
	        break;
        	case CKM_RC5_ECB : mechString ="CKM_RC5_ECB";
	        break;
        	case CKM_RC5_CBC : mechString ="CKM_RC5_CBC";
	        break;
        	case CKM_RC5_MAC : mechString ="CKM_RC5_MAC";
	        break;
        	case CKM_RC5_MAC_GENERAL : mechString ="CKM_RC5_MAC_GENERAL";
	        break;
        	case CKM_RC5_CBC_PAD : mechString ="CKM_RC5_CBC_PAD";
	        break;
        	case CKM_IDEA_KEY_GEN : mechString ="CKM_IDEA_KEY_GEN";
	        break;
        	case CKM_IDEA_ECB : mechString ="CKM_IDEA_ECB";
	        break;
        	case CKM_IDEA_CBC : mechString ="CKM_IDEA_CBC";
	        break;
        	case CKM_IDEA_MAC : mechString ="CKM_IDEA_MAC";
	        break;
        	case CKM_IDEA_MAC_GENERAL : mechString ="CKM_IDEA_MAC_GENERAL";
	        break;
        	case CKM_IDEA_CBC_PAD : mechString ="CKM_IDEA_CBC_PAD";
	        break;
        	case CKM_GENERIC_SECRET_KEY_GEN : mechString ="CKM_GENERIC_SECRET_KEY_GEN";
	        break;
        	case CKM_CONCATENATE_BASE_AND_KEY : mechString ="CKM_CONCATENATE_BASE_AND_KEY";
	        break;
        	case CKM_CONCATENATE_BASE_AND_DATA : mechString ="CKM_CONCATENATE_BASE_AND_DATA";
	        break;
        	case CKM_CONCATENATE_DATA_AND_BASE : mechString ="CKM_CONCATENATE_DATA_AND_BASE";
	        break;
        	case CKM_XOR_BASE_AND_DATA : mechString ="CKM_XOR_BASE_AND_DATA";
	        break;
        	case CKM_EXTRACT_KEY_FROM_KEY : mechString ="CKM_EXTRACT_KEY_FROM_KEY";
	        break;
        	case CKM_SSL3_PRE_MASTER_KEY_GEN : mechString ="CKM_SSL3_PRE_MASTER_KEY_GEN";
	        break;
	        case CKM_SSL3_MASTER_KEY_DERIVE : mechString ="CKM_SSL3_MASTER_KEY_DERIVE";
        	break;
        	case CKM_SSL3_KEY_AND_MAC_DERIVE : mechString ="CKM_SSL3_KEY_AND_MAC_DERIVE";
	        break;
        	case CKM_SSL3_MASTER_KEY_DERIVE_DH : mechString ="CKM_SSL3_MASTER_KEY_DERIVE_DH";
	        break;
        	case CKM_TLS_PRE_MASTER_KEY_GEN : mechString ="CKM_TLS_PRE_MASTER_KEY_GEN";
        	break;
	        case CKM_TLS_MASTER_KEY_DERIVE : mechString ="CKM_TLS_MASTER_KEY_DERIVE";
	        break;
        	case CKM_TLS_KEY_AND_MAC_DERIVE : mechString ="CKM_TLS_KEY_AND_MAC_DERIVE";
	        break;
        	case CKM_TLS_MASTER_KEY_DERIVE_DH : mechString ="CKM_TLS_MASTER_KEY_DERIVE_DH";
	        break;
        	case CKM_TLS_PRF : mechString ="CKM_TLS_PRF";
	        break;
        	case CKM_SSL3_MD5_MAC : mechString ="CKM_SSL3_MD5_MAC";
	        break;
        	case CKM_SSL3_SHA1_MAC : mechString ="CKM_SSL3_SHA1_MAC";
	        break;
        	case CKM_MD5_KEY_DERIVATION : mechString ="CKM_MD5_KEY_DERIVATION";
	        break;
	        case CKM_MD2_KEY_DERIVATION : mechString ="CKM_MD2_KEY_DERIVATION";
        	break;
	        case CKM_SHA1_KEY_DERIVATION : mechString ="CKM_SHA1_KEY_DERIVATION";
        	break;
	        case CKM_SHA256_KEY_DERIVATION : mechString ="CKM_SHA256_KEY_DERIVATION";
        	break;
	        case CKM_SHA384_KEY_DERIVATION : mechString ="CKM_SHA384_KEY_DERIVATION";
        	break;
	        case CKM_SHA512_KEY_DERIVATION : mechString ="CKM_SHA512_KEY_DERIVATION";
        	break;
	        case CKM_PBE_MD2_DES_CBC : mechString ="CKM_PBE_MD2_DES_CBC";
        	break;
	        case CKM_PBE_MD5_DES_CBC : mechString ="CKM_PBE_MD5_DES_CBC";
        	break;
	        case CKM_PBE_MD5_CAST_CBC : mechString ="CKM_PBE_MD5_CAST_CBC";
        	break;
	        case CKM_PBE_MD5_CAST3_CBC : mechString ="CKM_PBE_MD5_CAST3_CBC";
        	break;
	        case CKM_PBE_MD5_CAST5_CBC : mechString ="CKM_PBE_MD5_CAST5_CBC";
        	break;
	        case CKM_PBE_SHA1_CAST5_CBC : mechString ="CKM_PBE_SHA1_CAST5_CBC";
        	break;
	        case CKM_PBE_SHA1_RC4_128 : mechString ="CKM_PBE_SHA1_RC4_128";
        	break;
	        case CKM_PBE_SHA1_RC4_40 : mechString ="CKM_PBE_SHA1_RC4_40";
        	break;
	        case CKM_PBE_SHA1_DES3_EDE_CBC : mechString ="CKM_PBE_SHA1_DES3_EDE_CBC";
        	break;
	        case CKM_PBE_SHA1_DES2_EDE_CBC : mechString ="CKM_PBE_SHA1_DES2_EDE_CBC";
        	break;
	        case CKM_PBE_SHA1_RC2_128_CBC : mechString ="CKM_PBE_SHA1_RC2_128_CBC";
        	break;
	        case CKM_PBE_SHA1_RC2_40_CBC : mechString ="CKM_PBE_SHA1_RC2_40_CBC";
        	break;
	        case CKM_PKCS5_PBKD2 : mechString ="CKM_PKCS5_PBKD2";
        	break;
	        case CKM_PBA_SHA1_WITH_SHA1_HMAC : mechString ="CKM_PBA_SHA1_WITH_SHA1_HMAC";
	        break;
	        case CKM_WTLS_PRE_MASTER_KEY_GEN : mechString ="CKM_WTLS_PRE_MASTER_KEY_GEN";
	        break;
	        case CKM_WTLS_MASTER_KEY_DERIVE : mechString ="CKM_WTLS_MASTER_KEY_DERIVE";
	        break;
	        case CKM_WTLS_PRF : mechString ="CKM_WTLS_PRF";
	        break;
	        case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE : mechString ="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
	        break;
	        case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE : mechString ="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
	        break;
	        case CKM_KEY_WRAP_LYNKS : mechString ="CKM_KEY_WRAP_LYNKS";
	        break;
	        case CKM_KEY_WRAP_SET_OAEP : mechString ="CKM_KEY_WRAP_SET_OAEP";
	        break;
	        case CKM_CMS_SIG : mechString ="CKM_CMS_SIG";
	        break;
	        case CKM_SKIPJACK_KEY_GEN : mechString ="CKM_SKIPJACK_KEY_GEN";
	        break;
	        case CKM_SKIPJACK_ECB64 : mechString ="CKM_SKIPJACK_ECB64";
	        break;
	        case CKM_SKIPJACK_CBC64 : mechString ="CKM_SKIPJACK_CBC64";
	        break;
	        case CKM_SKIPJACK_OFB64 : mechString ="CKM_SKIPJACK_OFB64";
	        break;
	        case CKM_SKIPJACK_CFB64 : mechString ="CKM_SKIPJACK_CFB64";
	        break;
	        case CKM_SKIPJACK_CFB32 : mechString ="CKM_SKIPJACK_CFB32";
	        break;
	        case CKM_SKIPJACK_CFB16 : mechString ="CKM_SKIPJACK_CFB16";
	        break;
	        case CKM_SKIPJACK_CFB8 : mechString ="CKM_SKIPJACK_CFB8";
	        break;
	        case CKM_SKIPJACK_WRAP : mechString ="CKM_SKIPJACK_WRAP";
	        break;
	        case CKM_SKIPJACK_PRIVATE_WRAP : mechString ="CKM_SKIPJACK_PRIVATE_WRAP";
	        break;
	        case CKM_SKIPJACK_RELAYX : mechString ="CKM_SKIPJACK_RELAYX";
	        break;
	        case CKM_KEA_KEY_PAIR_GEN : mechString ="CKM_KEA_KEY_PAIR_GEN";
	        break;
	        case CKM_KEA_KEY_DERIVE : mechString ="CKM_KEA_KEY_DERIVE";
	        break;
	        case CKM_FORTEZZA_TIMESTAMP : mechString ="CKM_FORTEZZA_TIMESTAMP";
	        break;
	        case CKM_BATON_KEY_GEN : mechString ="CKM_BATON_KEY_GEN";
	        break;
	        case CKM_BATON_ECB128 : mechString ="CKM_BATON_ECB128";
	        break;
	        case CKM_BATON_ECB96 : mechString ="CKM_BATON_ECB96";
	        break;
	        case CKM_BATON_CBC128 : mechString ="CKM_BATON_CBC128";
	        break;
	        case CKM_BATON_COUNTER : mechString ="CKM_BATON_COUNTER";
	        break;
	        case CKM_BATON_SHUFFLE : mechString ="CKM_BATON_SHUFFLE";
	        break;
	        case CKM_BATON_WRAP : mechString ="CKM_BATON_WRAP";
	        break;
	        case CKM_ECDSA_KEY_PAIR_GEN : mechString ="CKM_ECDSA_KEY_PAIR_GEN";
	        break;
	        case CKM_ECDSA : mechString ="CKM_ECDSA";
	        break;
	        case CKM_ECDSA_SHA1 : mechString ="CKM_ECDSA_SHA1";
	        break;
	        case CKM_ECDH1_DERIVE : mechString ="CKM_ECDH1_DERIVE";
	        break;
	        case CKM_ECDH1_COFACTOR_DERIVE : mechString ="CKM_ECDH1_COFACTOR_DERIVE";
	        break;
	        case CKM_ECMQV_DERIVE : mechString ="CKM_ECMQV_DERIVE";
	        break;
	        case CKM_JUNIPER_KEY_GEN : mechString ="CKM_JUNIPER_KEY_GEN";
	        break;
	        case CKM_JUNIPER_ECB128 : mechString ="CKM_JUNIPER_ECB128";
	        break;
	        case CKM_JUNIPER_CBC128 : mechString ="CKM_JUNIPER_CBC128";
	        break;
	        case CKM_JUNIPER_COUNTER : mechString ="CKM_JUNIPER_COUNTER";
	        break;
	        case CKM_JUNIPER_SHUFFLE : mechString ="CKM_JUNIPER_SHUFFLE";
	        break;
	        case CKM_JUNIPER_WRAP : mechString ="CKM_JUNIPER_WRAP";
	        break;
	        case CKM_FASTHASH : mechString ="CKM_FASTHASH";
	        break;
	        case CKM_AES_KEY_GEN : mechString ="CKM_AES_KEY_GEN";
	        break;
	        case CKM_AES_ECB : mechString ="CKM_AES_ECB";
	        break;
	        case CKM_AES_CBC : mechString ="CKM_AES_CBC";
	        break;
	        case CKM_AES_MAC : mechString ="CKM_AES_MAC";
	        break;
	        case CKM_AES_MAC_GENERAL : mechString ="CKM_AES_MAC_GENERAL";
	        break;
	        case CKM_AES_CBC_PAD : mechString ="CKM_AES_CBC_PAD";
	        break;
	        case CKM_BLOWFISH_KEY_GEN : mechString ="CKM_BLOWFISH_KEY_GEN";
	        break;
	        case CKM_BLOWFISH_CBC : mechString ="CKM_BLOWFISH_CBC";
	        break;
	        case CKM_TWOFISH_KEY_GEN : mechString ="CKM_TWOFISH_KEY_GEN";
	        break;
	        case CKM_TWOFISH_CBC : mechString ="CKM_TWOFISH_CBC";
	        break;
	        case CKM_DES_ECB_ENCRYPT_DATA : mechString ="CKM_DES_ECB_ENCRYPT_DATA";
	        break;
	        case CKM_DES_CBC_ENCRYPT_DATA : mechString ="CKM_DES_CBC_ENCRYPT_DATA";
	        break;
	        case CKM_DES3_ECB_ENCRYPT_DATA : mechString ="CKM_DES3_ECB_ENCRYPT_DATA";
	        break;
	        case CKM_DES3_CBC_ENCRYPT_DATA : mechString ="CKM_DES3_CBC_ENCRYPT_DATA";
	        break;
	        case CKM_AES_ECB_ENCRYPT_DATA : mechString ="CKM_AES_ECB_ENCRYPT_DATA";
	        break;
	        case CKM_AES_CBC_ENCRYPT_DATA : mechString ="CKM_AES_CBC_ENCRYPT_DATA";
	        break;
	        case CKM_DSA_PARAMETER_GEN : mechString ="CKM_DSA_PARAMETER_GEN";
	        break;
	        case CKM_DH_PKCS_PARAMETER_GEN : mechString ="CKM_DH_PKCS_PARAMETER_GEN";
	        break;
	        case CKM_X9_42_DH_PARAMETER_GEN : mechString ="CKM_X9_42_DH_PARAMETER_GEN";
	        break;
	        case CKM_CAST_KEY_GEN_OLD_XXX : mechString ="CKM_CAST_KEY_GEN_OLD_XXX";
	        break;
	        case CKM_CAST_ECB_OLD_XXX : mechString ="CKM_CAST_ECB_OLD_XXX";
	        break;
	        case CKM_CAST_CBC_OLD_XXX : mechString ="CKM_CAST_CBC_OLD_XXX";
	        break;
	        case CKM_CAST_MAC_OLD_XXX : mechString ="CKM_CAST_MAC_OLD_XXX";
	        break;
	        case CKM_CAST3_KEY_GEN_OLD_XXX : mechString ="CKM_CAST3_KEY_GEN_OLD_XXX";
	        break;
	        case CKM_CAST3_ECB_OLD_XXX : mechString ="CKM_CAST3_ECB_OLD_XXX";
	        break;
	        case CKM_CAST3_CBC_OLD_XXX : mechString ="CKM_CAST3_CBC_OLD_XXX";
	        break;
	        case CKM_CAST3_MAC_OLD_XXX : mechString ="CKM_CAST3_MAC_OLD_XXX";
	        break;
	        case CKM_PBE_MD2_DES_CBC_OLD_XXX : mechString ="CKM_PBE_MD2_DES_CBC_OLD_XXX";
	        break;
	        case CKM_PBE_MD5_DES_CBC_OLD_XXX : mechString ="CKM_PBE_MD5_DES_CBC_OLD_XXX";
	        break;
	        case CKM_PBE_MD5_CAST_CBC_OLD_XXX : mechString ="CKM_PBE_MD5_CAST_CBC_OLD_XXX";
	        break;
	        case CKM_PBE_MD5_CAST3_CBC_OLD_XXX : mechString ="CKM_PBE_MD5_CAST3_CBC_OLD_XXX";
	        break;
	        case CKM_CONCATENATE_BASE_AND_KEY_OLD_XXX : mechString ="CKM_CONCATENATE_BASE_AND_KEY_OLD_XXX";
	        break;
	        case CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX : mechString ="CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX";
	        break;
	        case CKM_CONCATENATE_BASE_AND_DATA_OLD_XXX : mechString ="CKM_CONCATENATE_BASE_AND_DATA_OLD_XXX";
	        break;
	        case CKM_CONCATENATE_DATA_AND_BASE_OLD_XXX : mechString ="CKM_CONCATENATE_DATA_AND_BASE_OLD_XXX";
	        break;
	        case CKM_XOR_BASE_AND_DATA_OLD_XXX : mechString ="CKM_XOR_BASE_AND_DATA_OLD_XXX";
	        break;
	        case CKM_EXTRACT_KEY_FROM_KEY_OLD_XXX : mechString ="CKM_EXTRACT_KEY_FROM_KEY_OLD_XXX";
	        break;
	        case CKM_MD5_KEY_DERIVATION_OLD_XXX : mechString ="CKM_MD5_KEY_DERIVATION_OLD_XXX";
	        break;
	        case CKM_MD2_KEY_DERIVATION_OLD_XXX : mechString ="CKM_MD2_KEY_DERIVATION_OLD_XXX";
	        break;
	        case CKM_SHA1_KEY_DERIVATION_OLD_XXX : mechString ="CKM_SHA1_KEY_DERIVATION_OLD_XXX";
	        break;
	        case CKM_GENERIC_SECRET_KEY_GEN_OLD_XXX : mechString ="CKM_GENERIC_SECRET_KEY_GEN_OLD_XXX";
	        break;
	        case CKM_CAST5_KEY_GEN_OLD_XXX : mechString ="CKM_CAST5_KEY_GEN_OLD_XXX";
	        break;
	        case CKM_CAST5_ECB_OLD_XXX : mechString ="CKM_CAST5_ECB_OLD_XXX";
	        break;
	        case CKM_CAST5_CBC_OLD_XXX : mechString ="CKM_CAST5_CBC_OLD_XXX";
	        break;
	        case CKM_CAST5_MAC_OLD_XXX : mechString ="CKM_CAST5_MAC_OLD_XXX";
	        break;
	        case CKM_PBE_SHA1_CAST5_CBC_OLD_XXX : mechString ="CKM_PBE_SHA1_CAST5_CBC_OLD_XXX";
	        break;
	        case CKM_KEY_TRANSLATION : mechString ="CKM_KEY_TRANSLATION";
	        break;
	        case CKM_XOR_BASE_AND_KEY : mechString ="CKM_XOR_BASE_AND_KEY";
	        break;
	        case CKM_2DES_KEY_DERIVATION : mechString ="CKM_2DES_KEY_DERIVATION";
	        break;
	        case CKM_INDIRECT_LOGIN_REENCRYPT : mechString ="CKM_INDIRECT_LOGIN_REENCRYPT";
	        break;
	        case CKM_PBE_SHA1_DES3_EDE_CBC_OLD : mechString ="CKM_PBE_SHA1_DES3_EDE_CBC_OLD";
	        break;
	        case CKM_PBE_SHA1_DES2_EDE_CBC_OLD : mechString ="CKM_PBE_SHA1_DES2_EDE_CBC_OLD";
	        break;
	        case CKM_HAS160 : mechString ="CKM_HAS160";
	        break;
	        case CKM_KCDSA_KEY_PAIR_GEN : mechString ="CKM_KCDSA_KEY_PAIR_GEN";
	        break;
	        case CKM_KCDSA_HAS160 : mechString ="CKM_KCDSA_HAS160";
	        break;
	        case CKM_SEED_KEY_GEN : mechString ="CKM_SEED_KEY_GEN";
	        break;
	        case CKM_SEED_ECB : mechString ="CKM_SEED_ECB";
	        break;
	        case CKM_SEED_CBC : mechString ="CKM_SEED_CBC";
	        break;
	        case CKM_SEED_CBC_PAD : mechString ="CKM_SEED_CBC_PAD";
	        break;
	        case CKM_SEED_MAC : mechString ="CKM_SEED_MAC";
	        break;
	        case CKM_SEED_MAC_GENERAL : mechString ="CKM_SEED_MAC_GENERAL";
	        break;
	        case CKM_KCDSA_SHA1 : mechString ="CKM_KCDSA_SHA1";
	        break;
	        case CKM_KCDSA_SHA224 : mechString ="CKM_KCDSA_SHA224";
	        break;
	        case CKM_KCDSA_SHA256 : mechString ="CKM_KCDSA_SHA256";
	        break;
	        case CKM_KCDSA_SHA384 : mechString ="CKM_KCDSA_SHA384";
	        break;
	        case CKM_KCDSA_SHA512 : mechString ="CKM_KCDSA_SHA512";
	        break;
	        case CKM_KCDSA_PARAMETER_GEN : mechString ="CKM_KCDSA_PARAMETER_GEN";
	        break;
	        case CKM_SHA224_RSA_PKCS_OLD : mechString ="CKM_SHA224_RSA_PKCS_OLD";
	        break;
	        case CKM_SHA224_RSA_PKCS_PSS_OLD : mechString ="CKM_SHA224_RSA_PKCS_PSS_OLD";
	        break;
	        case CKM_SHA224_OLD : mechString ="CKM_SHA224_OLD";
	        break;
	        case CKM_SHA224_HMAC_OLD : mechString ="CKM_SHA224_HMAC_OLD";
	        break;
	        case CKM_SHA224_HMAC_GENERAL_OLD : mechString ="CKM_SHA224_HMAC_GENERAL_OLD";
	        break;
	        case CKM_SHA224_KEY_DERIVATION_OLD : mechString ="CKM_SHA224_KEY_DERIVATION_OLD";
	        break;
	        case CKM_DES3_CTR : mechString ="CKM_DES3_CTR";
	        break;
	        case CKM_AES_CFB8 : mechString ="CKM_AES_CFB8";
	        break;
	        case CKM_AES_CFB128 : mechString ="CKM_AES_CFB128";
	        break;
	        case CKM_AES_OFB : mechString ="CKM_AES_OFB";
	        break;
	        case CKM_AES_GCM_2_20a5d1 : mechString ="CKM_AES_GCM_2_20a5d1";
	        break;
	        case CKM_ARIA_CFB8 : mechString ="CKM_ARIA_CFB8";
	        break;
	        case CKM_ARIA_CFB128 : mechString ="CKM_ARIA_CFB128";
	        break;
	        case CKM_ARIA_OFB : mechString ="CKM_ARIA_OFB";
	        break;
	        case CKM_ARIA_CTR : mechString ="CKM_ARIA_CTR";
	        break;
	        case CKM_ARIA_GCM : mechString ="CKM_ARIA_GCM";
	        break;
	        case CKM_ECDSA_SHA224 : mechString ="CKM_ECDSA_SHA224";
	        break;
	        case CKM_ECDSA_SHA256 : mechString ="CKM_ECDSA_SHA256";
	        break;
	        case CKM_ECDSA_SHA384 : mechString ="CKM_ECDSA_SHA384";
	        break;
	        case CKM_ECDSA_SHA512 : mechString ="CKM_ECDSA_SHA512";
	        break;
	        case CKM_AES_GMAC : mechString ="CKM_AES_GMAC";
	        break;
	        case CKM_ARIA_CMAC : mechString ="CKM_ARIA_CMAC";
	        break;
	        case CKM_ARIA_CMAC_GENERAL : mechString ="CKM_ARIA_CMAC_GENERAL";
	        break;
	        case CKM_SEED_CMAC : mechString ="CKM_SEED_CMAC";
	        break;
	        case CKM_SEED_CMAC_GENERAL : mechString ="CKM_SEED_CMAC_GENERAL";
	        break;
	        case CKM_DES3_CBC_PAD_IPSEC_OLD : mechString ="CKM_DES3_CBC_PAD_IPSEC_OLD";
	        break;
	        case CKM_DES3_CBC_PAD_IPSEC : mechString ="CKM_DES3_CBC_PAD_IPSEC";
	        break;
	        case CKM_AES_CBC_PAD_IPSEC : mechString ="CKM_AES_CBC_PAD_IPSEC";
	        break;
	        case CKM_ARIA_L_ECB : mechString ="CKM_ARIA_L_ECB";
	        break;
	        case CKM_ARIA_L_CBC : mechString ="CKM_ARIA_L_CBC";
	        break;
	        case CKM_ARIA_L_CBC_PAD : mechString ="CKM_ARIA_L_CBC_PAD";
	        break;
	        case CKM_ARIA_L_MAC : mechString ="CKM_ARIA_L_MAC";
	        break;
	        case CKM_ARIA_L_MAC_GENERAL : mechString ="CKM_ARIA_L_MAC_GENERAL";
	        break;
	        case CKM_SHA224_RSA_X9_31 : mechString ="CKM_SHA224_RSA_X9_31";
	        break;
	        case CKM_SHA256_RSA_X9_31 : mechString ="CKM_SHA256_RSA_X9_31";
	        break;
	        case CKM_SHA384_RSA_X9_31 : mechString ="CKM_SHA384_RSA_X9_31";
	        break;
	        case CKM_SHA512_RSA_X9_31 : mechString ="CKM_SHA512_RSA_X9_31";
	        break;
	        case CKM_SHA1_RSA_X9_31_NON_FIPS : mechString ="CKM_SHA1_RSA_X9_31_NON_FIPS";
	        break;
	        case CKM_SHA224_RSA_X9_31_NON_FIPS : mechString ="CKM_SHA224_RSA_X9_31_NON_FIPS";
	        break;
	        case CKM_SHA256_RSA_X9_31_NON_FIPS : mechString ="CKM_SHA256_RSA_X9_31_NON_FIPS";
	        break;
	        case CKM_SHA384_RSA_X9_31_NON_FIPS : mechString ="CKM_SHA384_RSA_X9_31_NON_FIPS";
	        break;
	        case CKM_SHA512_RSA_X9_31_NON_FIPS : mechString ="CKM_SHA512_RSA_X9_31_NON_FIPS";
	        break;
	        case CKM_RSA_X9_31_NON_FIPS : mechString ="CKM_RSA_X9_31_NON_FIPS";
	        break;
	        case CKM_DSA_SHA224 : mechString ="CKM_DSA_SHA224";
	        break;
	        case CKM_DSA_SHA256 : mechString ="CKM_DSA_SHA256";
	        break;
	        case CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN : mechString ="CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN";
	        break;
	        case CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN : mechString ="CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN";
	        break;
	        case CKM_SEED_CTR : mechString ="CKM_SEED_CTR";
	        break;
	        case CKM_KCDSA_HAS160_NO_PAD : mechString ="CKM_KCDSA_HAS160_NO_PAD";
	        break;
	        case CKM_KCDSA_SHA1_NO_PAD : mechString ="CKM_KCDSA_SHA1_NO_PAD";
	        break;
	        case CKM_KCDSA_SHA224_NO_PAD : mechString ="CKM_KCDSA_SHA224_NO_PAD";
	        break;
	        case CKM_KCDSA_SHA256_NO_PAD : mechString ="CKM_KCDSA_SHA256_NO_PAD";
	        break;
	        case CKM_KCDSA_SHA384_NO_PAD : mechString ="CKM_KCDSA_SHA384_NO_PAD";
	        break;
	        case CKM_KCDSA_SHA512_NO_PAD : mechString ="CKM_KCDSA_SHA512_NO_PAD";
	        break;
	        case CKM_DES3_X919_MAC : mechString ="CKM_DES3_X919_MAC";
	        break;
	        case CKM_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS : mechString ="CKM_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS";
	        break;
	        case CKM_ECDSA_GBCS_SHA256 : mechString ="CKM_ECDSA_GBCS_SHA256";
	        break;
	        case CKM_AES_KW : mechString ="CKM_AES_KW";
	        break;
	        case CKM_AES_KWP : mechString ="CKM_AES_KWP";
	        break;
	        case CKM_TDEA_KW : mechString ="CKM_TDEA_KW";
	        break;
	        case CKM_TDEA_KWP : mechString ="CKM_TDEA_KWP";
	        break;
	        case CKM_AES_CBC_PAD_EXTRACT : mechString ="CKM_AES_CBC_PAD_EXTRACT";
	        break;
	        case CKM_AES_CBC_PAD_INSERT : mechString ="CKM_AES_CBC_PAD_INSERT";
	        break;
	        case CKM_AES_CBC_PAD_EXTRACT_FLATTENED : mechString ="CKM_AES_CBC_PAD_EXTRACT_FLATTENED";
	        break;
	        case CKM_AES_CBC_PAD_INSERT_FLATTENED : mechString ="CKM_AES_CBC_PAD_INSERT_FLATTENED";
	        break;
	        case CKM_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL : mechString ="CKM_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL";
	        break;
	        case CKM_AES_CBC_PAD_INSERT_DOMAIN_CTRL : mechString ="CKM_AES_CBC_PAD_INSERT_DOMAIN_CTRL";
	        break;
	        case CKM_PLACE_HOLDER_FOR_ERACOME_DEF_IN_SHIM : mechString ="CKM_PLACE_HOLDER_FOR_ERACOME_DEF_IN_SHIM";
	        break;
	        case CKM_DES2_DUKPT_PIN : mechString ="CKM_DES2_DUKPT_PIN";
	        break;
	        case CKM_DES2_DUKPT_MAC : mechString ="CKM_DES2_DUKPT_MAC";
	        break;
	        case CKM_DES2_DUKPT_MAC_RESP : mechString ="CKM_DES2_DUKPT_MAC_RESP";
	        break;
	        case CKM_DES2_DUKPT_DATA : mechString ="CKM_DES2_DUKPT_DATA";
	        break;
	        case CKM_DES2_DUKPT_DATA_RESP : mechString ="CKM_DES2_DUKPT_DATA_RESP";
	        break;
	        case CKM_ECIES : mechString ="CKM_ECIES";
	        break;
	        case CKM_XOR_BASE_AND_DATA_W_KDF : mechString ="CKM_XOR_BASE_AND_DATA_W_KDF";
	        break;
	        case CKM_NIST_PRF_KDF : mechString ="CKM_NIST_PRF_KDF";
	        break;
	        case CKM_PRF_KDF : mechString ="CKM_PRF_KDF";
	        break;
	        case CKM_AES_XTS : mechString ="CKM_AES_XTS";
	        break;
	        case CKM_SM3 : mechString ="CKM_SM3";
	        break;
	        case CKM_SM3_HMAC : mechString ="CKM_SM3_HMAC";
	        break;
	        case CKM_SM3_HMAC_GENERAL : mechString ="CKM_SM3_HMAC_GENERAL";
	        break;
	        case CKM_SM3_KEY_DERIVATION : mechString ="CKM_SM3_KEY_DERIVATION";
	        break;
	        case CKM_EC_EDWARDS_KEY_PAIR_GEN : mechString ="CKM_EC_EDWARDS_KEY_PAIR_GEN";
	        break;
	        case CKM_EDDSA_NACL : mechString ="CKM_EDDSA_NACL";
	        break;
	        case CKM_EDDSA : mechString ="CKM_EDDSA";
	        break;
	        case CKM_SHA1_EDDSA_NACL : mechString ="CKM_SHA1_EDDSA_NACL";
	        break;
	        case CKM_SHA224_EDDSA_NACL : mechString ="CKM_SHA224_EDDSA_NACL";
	        break;
	        case CKM_SHA256_EDDSA_NACL : mechString ="CKM_SHA256_EDDSA_NACL";
	        break;
	        case CKM_SHA384_EDDSA_NACL : mechString ="CKM_SHA384_EDDSA_NACL";
	        break;
	        case CKM_SHA512_EDDSA_NACL : mechString ="CKM_SHA512_EDDSA_NACL";
	        break;
	        case CKM_SHA1_EDDSA : mechString ="CKM_SHA1_EDDSA";
	        break;
	        case CKM_SHA224_EDDSA : mechString ="CKM_SHA224_EDDSA";
	        break;
	        case CKM_SHA256_EDDSA : mechString ="CKM_SHA256_EDDSA";
	        break;
	        case CKM_SHA384_EDDSA : mechString ="CKM_SHA384_EDDSA";
	        break;
	        case CKM_SHA512_EDDSA : mechString ="CKM_SHA512_EDDSA";
	        break;
	        case CKM_EC_MONTGOMERY_KEY_PAIR_GEN : mechString ="CKM_EC_MONTGOMERY_KEY_PAIR_GEN";
	        break;
	    }
    printf(" | %s",mechString);
}

// This function displays the list of all mechanisms supported by the firmware.
void getMechanisms()
{
	CK_MECHANISM_TYPE *mechList=NULL;
	CK_ULONG listSize = 0;
	checkOperation(p11Func->C_GetMechanismList(slotId, NULL_PTR, &listSize), "C_GetMechanismList");
	mechList = (CK_MECHANISM_TYPE_PTR)malloc(listSize * sizeof(CK_MECHANISM_TYPE));
	checkOperation(p11Func->C_GetMechanismList(slotId, mechList, &listSize), "C_GetMechanismList");
	printf("\n> Supported Mechanisms - \n");
	for(int ctr=0;ctr<listSize;ctr++)
	{
		printf("%d.",ctr);
		displayMechanismName(mechList[ctr]);
		printf(" | 0x%1X\n", (unsigned int)mechList[ctr]);
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
	checkOperation(p11Func->C_Initialize(NULL_PTR), "C_Initialize"); // Initialize cryptoki.
	getMechanisms();
	checkOperation(p11Func->C_Finalize(NULL_PTR), "C_Finalize"); // finalize cryptoki.
	freeMem();
	return 0;
}
