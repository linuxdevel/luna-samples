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
	- This sample demonstrates how to perform encryption using AES/GCM/NoPadding mode.
	- This sample is suitable for Luna HSMs configured to operate in NON-FIPS mode, i.e. HSM POLICY 12 : ON.
	- This sample would fail if used with a Luna HSM configured to operate in FIPS mode.
*/


import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class EncryptUsing_AESGCM {

	private static String slotLabel = null;
	private static String slotPassword = null;
	private static LunaSlotManager slotManager = null;
	private static byte[] encryptedData = null;
	private static byte[] decryptedData = null;
	private static SecretKey encryptionKey = null;
	private static GCMParameterSpec gcmSpec = null;
	private static byte[] initializationVector = "1123581321345589".getBytes();
	private static final String PLAINTEXT = "Earth is the third planet of our Solar System.";
	private static final String PROVIDER = "LunaProvider";
	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int KEY_SIZE = 256;
	private static final int TAG_BITS = 128;
	private static final byte[] AAD = "1234".getBytes();

	// Prints command usage.
	private static void printUsage() {
		System.out.println(" [ EncryptUsing_AESGCM ]\n");
		System.out.println("Usage-");
		System.out.println("java EncryptUsing_AESGCM <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java EncryptUsing_AESGCM myPartition userpin\n");
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


	// Encrypts plaintext using AES-GCM
	private static void encryptData() throws Exception {
		gcmSpec = new GCMParameterSpec(TAG_BITS, initializationVector); // initializing GCMParamaters with tagbit and IV.
		Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding", PROVIDER);
		encrypt.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmSpec);
		encrypt.updateAAD(AAD); // (optional)update additional authentication data. 
		encryptedData = encrypt.doFinal(PLAINTEXT.getBytes());
		System.out.println("Plaintext encrypted.");
	}


	// Decrypts the ciphertext AES-GCM
	private static void decryptData() throws Exception {
		gcmSpec = new GCMParameterSpec(TAG_BITS, initializationVector); // initializing GCMParamaters with tagbit and IV used during encryption.
		Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding", PROVIDER);
		decrypt.init(Cipher.DECRYPT_MODE, encryptionKey, gcmSpec);
		decrypt.updateAAD(AAD); // update additional authentication data. Without this decryption would fail. required if aad was used during encryption.
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
