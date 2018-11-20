/* openssl genrsa -out keypair.pem 2048
 * openssl rsa -in keypair.pem -outform DER -pubout -out public.der
 * openssl pkcs8 -topk8 -nocrypt -in keypair.pem -outform DER -out private.der
 */

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ValidateSignature {

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Test file or signature file location is missing.");
            System.out.println("Eg: java GenerateSignature test.txt signature.txt");
            return;
        } 

        try {
            PublicKey publicKey = readPublicKey(System.getProperty("user.dir") + "/certs/public.der");
            PrivateKey privateKey = readPrivateKey(System.getProperty("user.dir") + "/certs/private.der");
            String testfile = System.getProperty("user.dir") + "/testFiles/" + args[0];

            validateSignature(publicKey, System.getProperty("user.dir") + "/testFiles/" + args[1], testfile);
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public static void validateSignature(PublicKey publicKey, String signaturefile, String testfile) {
        try {
            FileInputStream sigfis = new FileInputStream(signaturefile);
            byte[] sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify);
            sigfis.close();

            sigToVerify = Base64.getDecoder().decode(new String(sigToVerify));


            /* create a Signature object and initialize it with the public key */
            Signature rsa = Signature.getInstance("SHA1withRSA");
            rsa.initVerify(publicKey);


            /* Update and verify the data */

            FileInputStream datafis = new FileInputStream(testfile);
            BufferedInputStream bufin = new BufferedInputStream(datafis);

            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                rsa.update(buffer, 0, len);
            }
            ;

            bufin.close();


            boolean verifies = rsa.verify(sigToVerify);

            System.out.println("signature verifies: " + verifies);


        } catch (Exception e) {            
            e.printStackTrace();
        }
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
