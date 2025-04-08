//key management

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class Master {
public static void main(String args[]) throws IOException, InvalidKeySpecException{
    keyGen();
}

static void keyGen() throws IOException, InvalidKeySpecException {
    try {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        String path = "C:\\Users\\dell\\Documents\\Removable Disk\\M\\hangFire";
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        
        SaveKeyPair(path, pair);
        
        PublicKey loadedPublic = LoadPublicKey(path, "\\public.key");
        //PrivateKey loadedPrivate = LoadPrivateKey(path, "\\private.key");
        Encrypt(loadedPublic, "truyr".toCharArray());
	} 
    catch (Exception ex) {}
}


@SuppressWarnings("unused")
private static void dumpKeyPair(KeyPair keyPair) {
		PublicKey pub = keyPair.getPublic();
                PrivateKey priv = keyPair.getPrivate();
                System.out.println("Public Key: " + getHexString(pub.getEncoded()));
                System.out.println("Private Key: " + getHexString(priv.getEncoded()) + "\n");
        }

private static String getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}


private static void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		fos = new FileOutputStream(path + "/private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}

private static PublicKey LoadPublicKey(String path, String f)throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File filePublicKey = new File(path + f);
		FileInputStream fis = new FileInputStream(path + f);
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}

@SuppressWarnings("unused")
private static PrivateKey LoadPrivateKey(String path, String f)throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File filePrivateKey = new File(path + f);
		FileInputStream fis = new FileInputStream(path + f);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
                
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                
        return privateKey;
}



@SuppressWarnings("unused")
private static byte [] generateIV() {
SecureRandom random = new SecureRandom();
byte [] iv = new byte [16];
random.nextBytes(iv);
return iv;
}

public static void Encrypt(PublicKey pubKey, char[] pwd) throws IllegalBlockSizeException, IllegalBlockSizeException, BadPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    PBEKeySpec pbeKeySpec;
    PBEParameterSpec pbeParamSpec;
    SecretKeyFactory keyFac;

    // Salt
    byte[] salt = new byte[8];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(salt);

    // Iteration count
    int count = 1000;

    // Create PBE parameter set
    pbeParamSpec = new PBEParameterSpec(salt, count);

    pbeKeySpec = new PBEKeySpec(pwd);

    keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

    // Create PBE Cipher
    Cipher pbeCipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");

    // Initialize PBE Cipher with key and parameters
    pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

    // Our clear text
    byte[] cleartext = "This is another example".getBytes();

    // Encrypt the clear text
    byte[] ciphertext = pbeCipher.doFinal(cleartext);
    System.out.println(ciphertext.toString());
} }