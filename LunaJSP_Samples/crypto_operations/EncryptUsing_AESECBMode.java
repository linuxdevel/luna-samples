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
	- This sample demonstrates how to perform encryption using AES/ECB/NoPadding mode.
	- This sample generates an AES-256 session key.
*/


import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class EncryptUsing_AESECBMode {

	private static String slotLabel = null;
	private static String slotPassword = null;
	private static LunaSlotManager slotManager = null;
	private static byte[] encryptedData = null; // For storing CipherText.
	private static byte[] decryptedData = null; // For storing decrypted text.
	private static SecretKey encryptionKey = null; // For storing encryption key.
	private static final String PLAINTEXT = "1234567812345678";
	private static final String PROVIDER = "LunaProvider";
	private static final int KEY_SIZE = 256;


	// Prints command usage.
	private static void printUsage() {
		System.out.println(" [ EncryptUsing_AESECBMode ]\n");
		System.out.println("Usage-");
		System.out.println("java EncryptUsing_AESECBMode <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java EncryptUsing_AESECBMode myPartition userpin\n");
	}


	// Add LunaProvider into security provider list.
	private static void addLunaProvider() {
		Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
	}


	// Perform C_Login
	private static void loginToLunaSlot() {
		if(slotManager.findSlotFromLabel(slotLabel)!=-1) {
			slotManager.login(slotLabel, slotPassword);
			System.out.println("Login : SUCCESS.");
		} else {
			System.out.println(slotLabel + " not found.");
			System.exit(1);
		}
	}


	// Generate AES key.
	private static void generateAESKey() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", PROVIDER);
		keyGenerator.init(KEY_SIZE);
		encryptionKey = keyGenerator.generateKey();
		System.out.println("AES key generated.");
	}


	// Encrypts plaintext.
	private static void encryptData() throws Exception {
		Cipher encrypt = Cipher.getInstance("AES/ECB/NoPadding", PROVIDER);
		encrypt.init(Cipher.ENCRYPT_MODE, encryptionKey);
		encryptedData = encrypt.doFinal(PLAINTEXT.getBytes());
		System.out.println("Plaintext encrypted.");
	}


	// Decrypts the ciphertext
	private static void decryptData() throws Exception {
		Cipher decrypt = Cipher.getInstance("AES/ECB/NoPadding", PROVIDER);
		decrypt.init(Cipher.DECRYPT_MODE, encryptionKey);
		decryptedData = decrypt.doFinal(encryptedData);
		System.out.println("Ciphertext decrypted.");
	}


	public static void main(String args[]) {
		try {

			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();
			loginToLunaSlot();
			addLunaProvider();
			generateAESKey();
			encryptData();
			decryptData();

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
