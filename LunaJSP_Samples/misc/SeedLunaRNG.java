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
	- This sample demonstrates how to use LunaRNG to generate randomized data.
	- LunaRNG will be seeded before it is used for generating random data.
	- This sample may fail for Luna Cloud HSM.
*/


import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.exception.*;
import java.security.*;

public class SeedLunaRNG {

	private static String slotPassword = null;
	private static String slotLabel = null;
	private static byte[] randomBytes = null;
	private static final String PROVIDER = "LunaProvider";

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ SeedLunaRNG ]\n");
		System.out.println("Usage-");
		System.out.println("java SeedLunaRNG <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java SeedLunaRNG myPartition userpin\n");
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


	// Generates random number using LunaRNG.
	private static void generateRandomData() throws Exception {
		SecureRandom rng = SecureRandom.getInstance("LunaRNG", "LunaProvider");
		randomBytes = new byte[32];
		rng.setSeed("1234567812345678".getBytes());
		rng.nextBytes(randomBytes);
		System.out.println("32 bytes of random data generated : " + LunaUtils.getHexString(randomBytes, false)); // getHexString(bytes,spacesInOutput)
	}

	public static void main(String args[]) {

		try {
			slotLabel = args[0];
			slotPassword = args[1];

			LunaSlotManager.getInstance().login(slotLabel, slotPassword); // Performs C_Login
			addLunaProvider();
			System.out.println("LOGIN: SUCCESS");

			generateRandomData();

			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			System.out.println("\nERROR: Please pass slot label and crypto-officer password as an argument.\n");
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exception) {
			System.out.println("Error: "+ exception.getMessage());
		}
	}
}
