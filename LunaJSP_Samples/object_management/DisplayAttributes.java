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
	- This sample demonstrates how to use LunaTokenObject to read pkcs11 attributes of an object.
	- LunaTokenObject can be utilized to read information such as keylabel, keytype, handle number, and pkcs11 attributes.
*/


import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaAPI;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.exception.*;

public class DisplayAttributes {

	private static int slotId;
	private static String slotPassword = null;
	private static int objectHandle;
	private static String ouid = null;
	private static LunaTokenObject tokenObject = null;

	private static void printUsage() {
		System.out.println(" [ DisplayAttributes ]\n");
		System.out.println("Usage-");
		System.out.println("\tjava DisplayAttributes <slot_number> <crypto_officer_password> -ouid ouid_string");
		System.out.println("\tor");
		System.out.println("\tjava DisplayAttributes <slot_number> <crypto_officer_password> -handle handle_number\n");
		System.out.println("Example -");
		System.out.println("\tjava DisplayAttributes 0 userpin1 -handle 56");
		System.out.println("\tjava DisplayAttributes 2 userpin1 -ouid 232b53kj25bc798000\n");
	}


	// Retrieve an object using OUID (Cloud HSM).
	private static void getObjectUsingOUID(String ouid) {
		tokenObject = LunaTokenObject.LocateObjectByOUID(LunaUtils.hexStringToByteArray(ouid), slotId);
		if(tokenObject==null) {
			System.out.println("Object with ouid '" + ouid + "' not found.");
			System.exit(1);
		}
	}


	// Retrieve an object using object handle.
        private static void getObjectUsingHandle(int handle) {
                tokenObject = LunaTokenObject.LocateObjectByHandle(handle);
                if(tokenObject==null) {
                        System.out.println("Object with handle '" + handle + "' not found.");
                        System.exit(1);
                }
        }


	// Displays attributes of an object.
	private static void displayObjectAttributes() {
		long classType[] = tokenObject.GetClassAndType();
		System.out.println("[");
		System.out.println("\tCKA_LABEL\t: " + new String(tokenObject.GetLargeAttribute(LunaAPI.CKA_LABEL)));
		System.out.println("\tCKA_ID   \t: " + LunaUtils.getHexString(tokenObject.GetLargeAttribute(LunaAPI.CKA_ID),false));
		System.out.println("\tCKA_CLASS\t: " + classType[0]);
		System.out.println("\tCKA_PRIVATE\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_PRIVATE));
		System.out.println("\tCKA_TOKEN\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_TOKEN));
		System.out.println("\tCKA_MODIFIABLE\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_MODIFIABLE));

		if (classType[0]==1) {
			System.out.println("\tCKA_VALUE\t: " + LunaUtils.getHexString(tokenObject.GetLargeAttribute(LunaAPI.CKA_VALUE), false));
		}

		if (classType[0]==3 || classType[0]==4) {
			System.out.println("\tCKA_SENSITIVE\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_SENSITIVE));
			System.out.println("\tCKA_EXTRACTABLE\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_EXTRACTABLE));
		}

		if (classType[0]==2 || classType[0]==4) {
			System.out.println("\tCKA_ENCRYPT\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_ENCRYPT));
			System.out.println("\tCKA_VERIFY\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_VERIFY));
			System.out.println("\tCKA_WRAP\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_WRAP));
		}

		if (classType[0]==3 || classType[0]==4) {
			System.out.println("\tCKA_DECRYPT\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_DECRYPT));
			System.out.println("\tCKA_SIGN\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_SIGN));
			System.out.println("\tCKA_UNWRAP\t: " + tokenObject.GetBooleanAttribute(LunaAPI.CKA_UNWRAP));
		}

		System.out.println("]");
	}


	public static void main(String args[]) {
		String option;
		try {
			slotId = Integer.parseInt(args[0]);
			slotPassword = args[1];
			LunaSlotManager.getInstance().login(slotId, slotPassword); // Performs C_Login

			option = args[2];
			switch(option) {
				case "-ouid": ouid = args[3]; getObjectUsingOUID(ouid);
				break;
				case "-handle": objectHandle = Integer.parseInt(args[3]); getObjectUsingHandle(objectHandle);
				break;
			}

			System.out.println("LOGIN: SUCCESS\n");
			displayObjectAttributes();
			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(NumberFormatException nfe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exp) {
			System.out.println("ERROR: "+ exp.getMessage());
		}
	}
}
