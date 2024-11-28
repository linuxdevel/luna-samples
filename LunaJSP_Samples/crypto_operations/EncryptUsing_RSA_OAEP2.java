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
	- This sample demonstrates how to generate an RSA-2048 keypair using LunaProvider and use it to perform encryption.
	- Keypair generated using this sample is ephemeral, i.e. a session keypair.
	- This sample uses CKM_RSA_PKCS_OAEP mechanism, which in java security is referred to as "RSA/None/OAEPWithSHA256AndMGF1Padding"".
*/


import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import javax.crypto.Cipher;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class EncryptUsing_RSA_OAEP2 {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair rsaKeyPair = null;
	private static final int KEY_SIZE = 2048;
	private static final String PROVIDER = "LunaProvider";
	private static final String PLAINTEXT = "Earth is the third planet of our Solar System.";
	private static byte[] encryptedData = null;
	private static byte[] decryptedData = null;


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ EncryptUsing_RSA_OAEP2 ]\n");
		System.out.println("Usage-");
		System.out.println("java EncryptUsing_RSA_OAEP2 <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java EncryptUsing_RSA_OAEP2 myPartition userpin\n");
	}

	// Adds LunaProvider into java security provider List dynamically.
	private static void addLunaProvider() {
		Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
	}

	// generates rsa-2048 keypair
	private static void generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA",PROVIDER);
		keyPairGen.initialize(KEY_SIZE);
		rsaKeyPair = keyPairGen.generateKeyPair();
		System.out.println("RSA-2048 keypair generated.");
	}

	// encrypts plaintext using CKM_RSA_PKCS mechanism.
	private static void encryptData() throws Exception {
		Cipher encrypt = Cipher.getInstance("RSA/None/OAEPWithSHA256AndMGF1Padding", PROVIDER);
		encrypt.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
		encryptedData = encrypt.doFinal(PLAINTEXT.getBytes());
		System.out.println("Plaintext encrypted.");
	}

	// decrypt the cipher text.
	private static void decryptData() throws Exception {
		Cipher decrypt = Cipher.getInstance("RSA/None/OAEPWithSHA256AndMGF1Padding", PROVIDER);
		decrypt.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
		decryptedData = decrypt.doFinal(encryptedData);
		System.out.println("Encrypted data decrypted.");
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			if(slotManager.findSlotFromLabel(slotLabel)!=-1) { // checks if the slot number is correct.
				addLunaProvider();
				slotManager.login(slotLabel, slotPassword); // Performs C_Login
				System.out.println("LOGIN: SUCCESS");
				generateKeyPair();
				encryptData();
				decryptData();
			} else {
				System.out.println("ERROR: Slot with label " + slotLabel + " not found.");
				System.exit(1);
			}

			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exception) {
			System.out.println("ERROR: "+ exception.getMessage());
		}
	}
}
