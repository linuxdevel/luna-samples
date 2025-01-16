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
	- This sample demonstrates how to retrieve a Private key from a Luna Partition using LunaKey.
	- LunaKey is a LunaProvider class that can be used as an easy alternative to save/retrieve key from a partition.
	- There are many different way to retrieve an object using LunaKey, this sample uses key label.
*/



import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.key.LunaKey;
import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.exception.*;

public class RetrievePrivateKeyUsingLunaKey {

	private static String slotLabel = null;
	private static String slotPassword = null;
	private static String keyLabel = null;

	private static void printUsage() {
		System.out.println(" [ RetrievePrivateKeyUsingLunaKey ]\n");
		System.out.println("Usage-");
		System.out.println("java RetrievePrivateKeyUsingLunaKey <slot_label> <crypto_officer_password> <key_label>\n");
		System.out.println("Example -");
		System.out.println("java RetrievePrivateKeyUsingLunaKey myPartition userpin myPrivateKey\n");
	}


	private static void findKey(String keyLabel) {
		LunaKey privateKey = LunaKey.LocateKeyByAlias(keyLabel);
		if(privateKey!=null) {
			System.out.println("Private Key " + keyLabel + " found.");
			System.out.println("Algorithm : " + privateKey.getAlgorithm());
			System.out.println("Created Date : " + privateKey.GetDateMadePersistent());
			System.out.println("Handle Number : " + privateKey.GetKeyHandle());
			System.out.println("OUID : " + LunaUtils.getHexString(privateKey.GetOUID(), false));
		}
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			keyLabel = args[2];
			LunaSlotManager.getInstance().login(slotLabel, slotPassword); // Performs C_Login
			System.out.println("LOGIN: SUCCESS");
			findKey(keyLabel);
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
