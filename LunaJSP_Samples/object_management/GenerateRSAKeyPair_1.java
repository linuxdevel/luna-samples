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
	- This sample demonstrates how to generate an RSA-2048 keypair using LunaProvider.
	- Keypair generated using this sample is ephemeral, i.e. a session keypair.

*/


import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class GenerateRSAKeyPair_1 {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair rsaKeyPair = null;
	private static final int KEY_SIZE = 2048;
	private static final String PROVIDER = "LunaProvider";

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ GenerateRSAKeyPair_1 ]\n");
		System.out.println("Usage-");
		System.out.println("java GenerateRSAKeyPair_1 <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java GenerateRSAKeyPair_1 myPartition userpin\n");
	}

	// Adds LunaProvider into java security provider List dynamically.
	private static void addLunaProvider() {
		Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
	}

	// generates rsa-2048 keypair
	private static void generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA",PROVIDER);
		keyPairGen.initialize(KEY_SIZE);
		rsaKeyPair = keyPairGen.generateKeyPair();
		System.out.println("RSA-2048 keypair generated.");
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
				generateKeyPair();
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
