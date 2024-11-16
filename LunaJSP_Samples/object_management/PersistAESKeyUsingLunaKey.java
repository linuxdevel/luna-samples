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
	- This sample uses LunaKey class to store key in a partition.

*/


import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.key.LunaKey;
import com.safenetinc.luna.exception.*;

public class PersistAESKeyUsingLunaKey {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static SecretKey aesKey = null;
	private static final int KEY_SIZE = 256;
	private static final String KEY_LABEL = "LUNA-SAMPLES-LUNAJSP-AES-KEY";

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ PersistAESKeyUsingLunaKey ]\n");
		System.out.println("Usage-");
		System.out.println("java PersistAESKeyUsingLunaKey <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java PersistAESKeyUsingLunaKey myPartition userpin\n");
	}

	// Adds LunaProvider into java security provider List dynamically.
	private static void addLunaProvider() {
		Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
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
	private static void storeKey() {
		LunaKey lunaKey = (LunaKey)aesKey;
		lunaKey.MakePersistent(KEY_LABEL);
		System.out.println("AES key saved with Label: " + KEY_LABEL + ".");
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			if(slotManager.findSlotFromLabel(slotLabel)!=-1) { // checks if the slot number is correct.
				addLunaProvider();
				slotManager.login(slotLabel, slotPassword); // Performs C_Login
				System.out.println("LOGIN: SUCCESS");
				generateKey();
				storeKey();
			} else {
				System.out.println("ERROR: Slot with label " + slotLabel + " not found.");
				System.exit(1);
			}

			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");

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
