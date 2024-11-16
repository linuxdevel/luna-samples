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
	- User will need to provide a slot label and the Crypto-Officer password to login.
	- This sample will attempt to login to the luna partition matching the user specified slot label.
	- Sample will exist if a slot with specified label is not found.
*/



import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.LunaException;

public class LoginLogoutUsingSlotLabel {

	private static String slotPassword = null;
	private static String slotLabel = null;
	private static LunaSlotManager slotManager = null;

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ LoginLogoutUsingSlotLabel ]\n");
		System.out.println("Usage-");
		System.out.println("java LoginLogoutUsingSlotLabel <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java LoginLogoutUsingSlotLabel myPartition userpin\n");
	}


	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			if(slotManager.findSlotFromLabel(slotLabel)!=-1) { // Checks if the slot exists.
				slotManager.login(slotLabel, slotPassword); // method in SlotManager used for login.
			} else {
				System.out.println("ERROR: Luna slot '" + slotLabel + "' not found.");
				System.exit(1);
			}

			System.out.println("LOGIN: SUCCESS");
			slotManager.logout();
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			System.out.println("\nERROR: Please pass a slot-label and crypto-officer password as an argument.\n");
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		}
	}
}
