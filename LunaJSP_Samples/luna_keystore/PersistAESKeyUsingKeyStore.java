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
	- This sample demonstrates how to generate an AES-256 key using LunaProvider.
	- Key generated using this sample persists in the HSM, i.e. Token Object.
	- This sample uses Luna KeyStore to persist key in a partition.

*/


import java.security.Security;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.io.ByteArrayInputStream;
import com.safenetinc.luna.exception.LunaException;

public class PersistAESKeyUsingKeyStore {

	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyStore lunaStore = null;
	private static SecretKey aesKey = null;
	private static final int KEY_SIZE = 256;
	private static final String KEY_LABEL = "LUNA-SAMPLES-LUNAJSP-AES-KEY";
	private static final String PROVIDER = "LunaProvider";

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ PersistAESKeyUsingKeyStore ]\n");
		System.out.println("Usage-");
		System.out.println("java PersistAESKeyUsingKeyStore <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java PersistAESKeyUsingKeyStore myPartition userpin\n");
	}


        // Add LunaProvider to security provider list.
        private static void addLunaProvider() {
                if(Security.getProvider(PROVIDER)==null) {
                        Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
                        System.out.println("LunaProvider added to java.security");
                } else {
                        System.out.println("LunaProvider found in java.security");
                }
        }


	// Loads Luna Keystore.
	private static void loadKeyStore() throws Exception {
		lunaStore = KeyStore.getInstance("Luna");
		lunaStore.load(new ByteArrayInputStream(("tokenlabel:"+slotLabel).getBytes()), slotPassword.toCharArray()); // Calls C_Login
		System.out.println("Luna KeyStore loaded.");
	}

	// generates aes-256 key.
	private static void generateKey() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES","LunaProvider");
		keyGen.init(KEY_SIZE);
		aesKey = keyGen.generateKey();
		if(aesKey!=null) {
			System.out.println("AES key generated.");
		}
	}

	// Stores aes-key as a token object
	private static void storeKey() throws Exception {
		lunaStore.setKeyEntry(KEY_LABEL, aesKey, null, (java.security.cert.Certificate[])null);
		System.out.println("AES key saved with Label: " + KEY_LABEL + ".");
	}


	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];

			addLunaProvider();
			loadKeyStore();
			generateKey();
			storeKey();
		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exception) {
			System.out.println("ERROR: "+ exception.getMessage());
		}
	}
}
