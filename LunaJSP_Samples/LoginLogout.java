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
	- Login will use Crypto-Officer password.
	- If multiple partitions are assigned to a client, this sample will attempt to login to the first available luna partition.
*/



import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class LoginLogout {
	private static String slotPassword = null;

	private static void printUsage() {
		System.out.println(" [ LoginLogout ]\n");
		System.out.println("Usage-");
		System.out.println("java LoginLogout <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java LoginLogout userpin\n");
	}

	public static void main(String args[]) {
		try {
			slotPassword = args[0];
			LunaSlotManager.getInstance().login(slotPassword); // Performs C_Login
			System.out.println("LOGIN: SUCCESS");
			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");
		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		}
	}
}
