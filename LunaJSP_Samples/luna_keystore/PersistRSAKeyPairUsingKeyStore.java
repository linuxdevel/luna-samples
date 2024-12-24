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
	- This sample demonstrates how to generate a persistent RSA-2048 key-pair using LunaProvider.
	- The key-pair generated using this sample will be made persistent using KeyStore class as a PrivateKeyEntry.

*/


import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Date;
import java.math.BigInteger;
import java.io.ByteArrayInputStream;
import com.safenetinc.luna.exception.*;
import com.safenetinc.luna.provider.LunaCertificateX509;

public class PersistRSAKeyPairUsingKeyStore {

	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair rsaKeyPair = null;
	private static final int KEY_SIZE = 2048;
	private static final String KEY_ALIAS = "LUNA-SAMPLE-RSA-KEY-ENTRY";
	private static final String PROVIDER = "LunaProvider";
	private static KeyStore lunaKeyStore = null;
	private static LunaCertificateX509 selfSigned = null;
	private static final long ONE_YEAR = 31556952000L;

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ PersistRSAKeyPairUsingKeyStore ]\n");
		System.out.println("Usage-");
		System.out.println("java PersistRSAKeyPairUsingKeyStore <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java PersistRSAKeyPairUsingKeyStore myPartition userpin\n");
	}

	// Adds LunaProvider into java security provider List dynamically.
	private static void addLunaProvider() {
		Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
	}

	// Loads Luna KeyStore and executes C_Login
	private static void loadKeyStore() throws Exception {
		lunaKeyStore = KeyStore.getInstance("Luna");
		lunaKeyStore.load(new ByteArrayInputStream(("tokenlabel:"+slotLabel).getBytes()), slotPassword.toCharArray());
		System.out.println("Luna Keystore loaded.");
	}

	// generates rsa-2048 keypair
	private static void generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA",PROVIDER);
		keyPairGen.initialize(KEY_SIZE);
		rsaKeyPair = keyPairGen.generateKeyPair();
		System.out.println("RSA-2048 keypair generated.");
	}

	// generate self-signed certificate for PrivateKeyEntry
	private static void generateSelfSignedCertificate() throws Exception {
		String subject = "CN=luna-samples, O=Thales, OU=Sales Engineering, C=CA";
		BigInteger serialNumber = BigInteger.valueOf(1123581321L);
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime()+ ONE_YEAR);
		selfSigned = LunaCertificateX509.SelfSign(rsaKeyPair, subject, serialNumber, notBefore, notAfter);

	}

	// Stores the generated keypair as Token Object
	private static void storeKeyPair() throws Exception {
		lunaKeyStore.setKeyEntry(KEY_ALIAS, rsaKeyPair.getPrivate(), null, new java.security.cert.Certificate[]{selfSigned});
		System.out.println("RSA Private key saved as PrivateKeyEntry in slot : [" + slotLabel + "]");
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];

			addLunaProvider();
			loadKeyStore();
			generateKeyPair();
			generateSelfSignedCertificate();
			storeKeyPair();

		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(Exception exception) {
			System.out.println("ERROR: "+ exception.getMessage());
		}
	}
}
