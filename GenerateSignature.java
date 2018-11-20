/* openssl genrsa -out keypair.pem 2048
 * openssl rsa -in keypair.pem -outform DER -pubout -out public.der
 * openssl pkcs8 -topk8 -nocrypt -in keypair.pem -outform DER -out private.der
 */
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class GenerateSignature {

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Test file location missing or signature file name is missing.");
            System.out.println("Eg: java GenerateSignature test.txt signature.txt");
            return;
        } 

        try {
            PublicKey publicKey = readPublicKey(System.getProperty("user.dir") + "/certs/public.der");
            PrivateKey privateKey = readPrivateKey(System.getProperty("user.dir") + "/certs/private.der");
            String testfile = System.getProperty("user.dir") + "/testFiles/" + args[0];


            getSignature(privateKey, testfile, "/testFiles/" + args[1]);
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }


    public static void getSignature(PrivateKey privateKey, String file, String signatureFile) {
        try {
            Signature rsa = Signature.getInstance("SHA1withRSA");
            rsa.initSign(privateKey);

            /* Update and sign the data */
            FileInputStream fis = new FileInputStream(file);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                rsa.update(buffer, 0, len);
            }
            bufin.close();

            /* Now that all the data to be signed has been read in,
                    generate a signature for it */

            byte[] realSig = rsa.sign();
            String realSig64 = Base64.getEncoder().encodeToString(realSig);
            /* Save the signature in a file */
            FileOutputStream sigfos = new FileOutputStream(System.getProperty("user.dir") + "/" + signatureFile);
            sigfos.write(realSig64.getBytes());

            sigfos.close();
            System.out.println("Signature is sotred to a file  " + signatureFile + "\n");
        } catch (Exception e) {
        }
    }

    public static byte[] encrypt(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static byte[] readFileBytes(String filename) throws IOException {
        Path path = Paths.get(filename);
        return Files.readAllBytes(path);
    }

    public static PublicKey readPublicKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(readFileBytes(filename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicSpec);
    }

    public static PrivateKey readPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
