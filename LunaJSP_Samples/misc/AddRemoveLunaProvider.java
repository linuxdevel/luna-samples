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
        - This sample demonstrates how dynamically add and remove LunaProvider as a Java Security provider.
        - This sample will display a list of all available providers before adding, after adding and removing LunaProvider.

*/

import java.security.Provider;
import java.security.Security;
import com.safenetinc.luna.provider.LunaProvider;

public class AddRemoveLunaProvider {

	// Display list of all available Java Security providers.
	private static void listProviders() {
		Provider []providers = Security.getProviders();
		for(Provider provider:providers) {
			System.out.println(provider);
		}
	}

	// Dynamically adds LunaProvider in Java Security provider list.
	private static void addLunaProvider() {
		Security.addProvider(new LunaProvider());
	}

	// Removes LunaProvider from Java Security Provider list.
	private static void removeLunaProvider() {
		Security.removeProvider("LunaProvider");
	}

	public static void main(String args[]) {

		System.out.println("----- BEFORE ADDING LUNA PROVIDER -----");
		listProviders();

		System.out.println("\n----- AFTER ADDING LUNA PROVIDER -----");
		addLunaProvider();
		listProviders();

		System.out.println("\n----- AFTER REMOVING LUNA PROVIDER -----");
		removeLunaProvider();
		listProviders();
		System.out.println();
	}
}

