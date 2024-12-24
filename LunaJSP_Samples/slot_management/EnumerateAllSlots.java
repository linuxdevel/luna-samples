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
	- This sample enumerates and displays a list of all luna slots/partitions.
	- Only TOKEN-PRESENT slots are enumerated. C_GetSlotList(CK_TRUE,,);
	- List also displays slot number, slot label, serial and firmware version.
*/



import com.safenetinc.luna.LunaSlotManager;

public class EnumerateAllSlots {

	private static int []detectedSlots; // to store all detected token-present slot number.
	private static LunaSlotManager slotManager = null;
	private static Long []firmware = null; // to store the firmware version.

	public static void main(String args[]) {

		slotManager = LunaSlotManager.getInstance();
		detectedSlots = slotManager.getSlotList(); // gets the list of all available slots.

		for(int slot:detectedSlots) {
			System.out.println("SLOT : " + slot);
			System.out.println("\tLabel     - " + slotManager.getTokenLabel(slot));
			System.out.println("\tSerial    - " + slotManager.getTokenSerialNumber(slot));
			firmware = slotManager.getTokenFirmwareVersion(slot);
			System.out.println("\tFirmware  - " + firmware[0] + "." + firmware[1] + "." + firmware[2]);
		}
	}
}
