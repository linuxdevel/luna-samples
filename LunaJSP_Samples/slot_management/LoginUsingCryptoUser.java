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
	- This sample shows how to login a luna partition using CRYPTO USER.
	- A CRYPTO USER grants read-only permission to a slot, i.e. write operations such as key generation, modification or deletion is disallowed.
	- CRYPTO USER must be initialized because running this sample.
*/



import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.UserRole;
import com.safenetinc.luna.exception.LunaException;
import com.safenetinc.luna.exception.LunaCryptokiException;

public class LoginUsingCryptoUser {

	private static int slotNumber;
	private static String slotPassword = null;
	private static LunaSlotManager slotManager = null;

	// Display correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ LoginUsingCryptoUser ]\n");
		System.out.println("Usage-");
		System.out.println("java LoginUsingCryptoUser <slot_number> <crypto_user_password>\n");
		System.out.println("Example -");
		System.out.println("java LoginUsingCryptoUser 0 cryptouser\n");
	}

	public static void main(String args[]) {
		try {
			slotNumber = Integer.parseInt(args[0]);
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			slotManager.login(slotNumber, UserRole.CRYPTO_USER, slotPassword); // Login using slot number and crypto user password.
			System.out.println("LOGIN: SUCCESS");

			slotManager.logout();
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			System.out.println("\nERROR: Please pass a slot-label and crypto-user password as an argument.\n");
			printUsage();
			System.exit(1);
		} catch(NumberFormatException nfe) {
			System.out.println("Slot number should be numeric.");
			System.exit(1);
		} catch(LunaCryptokiException lce) {
		        System.out.println("ERRORL "+ lce.getMessage());
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		}
	}
}
