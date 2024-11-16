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
	- This sample demonstrates how to login and then logout from a luna partition.
	- User will need to provide a slot number and the Crypto-Officer password to login.
	- This sample will attempt to login to the user specified slot number.
	- Sample will exist if the specified slot is not found.
*/



import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.LunaException;
import com.safenetinc.luna.exception.LunaCryptokiException;

public class LoginLogoutUsingSlotNumber {

	private static int slotNumber;
	private static String slotPassword = null;
	private static LunaSlotManager slotManager = null;

	// Display correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ LoginLogoutUsingSlotNumber ]\n");
		System.out.println("Usage-");
		System.out.println("java LoginLogoutUsingSlotNumber <slot_number> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java LoginLogoutUsingSlotNumber 0 userpin\n");
	}


	public static void main(String args[]) {
		try {
			slotNumber = Integer.parseInt(args[0]);
			slotPassword = args[1];

			slotManager = LunaSlotManager.getInstance();

			slotManager.login(slotNumber, slotPassword); // Login using slot number and crypto officer password.
			System.out.println("LOGIN: SUCCESS");

			slotManager.logout();
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			System.out.println("\nERROR: Please pass a slot-label and crypto-officer password as an argument.\n");
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
