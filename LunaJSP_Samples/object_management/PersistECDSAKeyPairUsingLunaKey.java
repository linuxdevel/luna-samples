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
	- This sample demonstrates how to generate a persistent ECDSA key-pair using LunaProvider.
	- The key-pair generated using this sample will be made persistent using LunaKey class.

*/


import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.spec.ECGenParameterSpec;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.key.LunaKey;
import com.safenetinc.luna.exception.*;

public class PersistECDSAKeyPairUsingLunaKey {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair ecdsaKeyPair = null;
	private static final String CURVE = "secp384r1";
	private static final String PROVIDER = "LunaProvider";


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ PersistECDSAKeyPairUsingLunaKey ]\n");
		System.out.println("Usage-");
		System.out.println("java PersistECDSAKeyPairUsingLunaKey <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java PersistECDSAKeyPairUsingLunaKey myPartition userpin\n");
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


	// generates ecdsa keypair
	private static void generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("ECDSA",PROVIDER);
		ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
		keyPairGen.initialize(ecSpec);
		ecdsaKeyPair = keyPairGen.generateKeyPair();
		System.out.println("ECDSA (" + CURVE + ") keypair generated.");
	}


	// Stores the generated keypair as Token Object
	private static void storeKeyPair() throws Exception {
		LunaKey eccPrivate = (LunaKey)ecdsaKeyPair.getPrivate();
		LunaKey eccPublic = (LunaKey)ecdsaKeyPair.getPublic();
		eccPrivate.MakePersistent("LUNA-SAMPLE-ECDSA-PRIVATE");
		eccPublic.MakePersistent("LUNA-SAMPLE-ECDSA-PUBLIC");
		System.out.println("ECDSA keypair saved in slot " + slotLabel);
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
				storeKeyPair();
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
