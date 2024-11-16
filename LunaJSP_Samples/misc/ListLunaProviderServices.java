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
        - This sample shows how list all services provided by LunaProvider.
*/

import java.security.Security;
import java.security.Provider;
import com.safenetinc.luna.provider.LunaProvider;

public class ListLunaProviderServices {

	// Adds LunaProvider into the list of Java Security Provider.
	private static void addLunaProvider() {
		Security.addProvider(new LunaProvider());
	}

	// Displays a list of all services provided by LunaProvider.
	private static void listServices() {
		Provider lunaProvider = Security.getProvider("LunaProvider");
		for(Provider.Service service:lunaProvider.getServices()) {
			System.out.println(service);
		}
	}

	public static void main(String args[]) {
		addLunaProvider();
		listServices();
	}
}
