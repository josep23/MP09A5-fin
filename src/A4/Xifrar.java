package A4;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class Xifrar {

        //1.1 public static SecretKey keygenKeyGeneration(int keySize)
        public static SecretKey keygenKeyGeneration(int keySize) {
            SecretKey sKey = null;
            if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
                try {
                    KeyGenerator kgen = KeyGenerator.getInstance("AES");
                    kgen.init(keySize);
                    sKey = kgen.generateKey();

                } catch (NoSuchAlgorithmException ex) {
                    System.err.println("Generador no disponible.");
                }
            }
            return sKey;
        }
        //1.2 public static SecretKey passwordKeyGeneration(String text, int keySize)
        public static SecretKey passwordKeyGeneration(String text, int keySize) {
            SecretKey sKey = null;
            if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
                try {
                    byte[] data = text.getBytes("UTF-8");
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] hash = md.digest(data);
                    byte[] key = Arrays.copyOf(hash, keySize / 8);
                    sKey = new SecretKeySpec(key, "AES");
                } catch (Exception ex) {
                    System.err.println("Error generant la clau:" + ex);
                }
            }
            return sKey;
        }

        //1.3 public static byte[] encryptData(byte[] data, SecretKey key)
        public static byte[] encryptData(SecretKey sKey, byte[] data) {
            byte[] encryptedData = null;
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, sKey);
                encryptedData = cipher.doFinal(data);

            } catch (Exception ex) {
                System.err.println("Error xifrant les dades: " + ex);
            }
            return encryptedData;
        }

        //1.4 public static byte[] decryptData(byte[] data, SecretKey key)
        public static byte[] decryptData(SecretKey sKey, byte[] data) {
            byte[] encryptedData = null;
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, sKey);
                encryptedData = cipher.doFinal(data);
            } catch (Exception ex) {
                System.err.println("Error desxifrant les dades: " + ex);
            }
            return encryptedData;
        }
        public static KeyPair randomGenerate(int len) {
            KeyPair keys = null;
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(len);
                keys = keyGen.genKeyPair();
            } catch (Exception ex) {
                System.err.println("Generador no disponible.");
            }
            return keys;
        }

         public static byte[] encryptData(byte[] data, PublicKey pub) {
            byte[] encryptedData = null;
            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
                cipher.init(Cipher.ENCRYPT_MODE, pub);
                encryptedData =  cipher.doFinal(data);
            } catch (Exception  ex) {
                System.err.println("Error xifrant: " + ex);
            }
            return encryptedData;
        }
        public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            File f = new File(ksFile);
            if (f.isFile()){
                FileInputStream in = new FileInputStream(f);
                ks.load(in,ksPwd.toCharArray());
            }

            return ks;

        }

        public static void meterLlave(KeyStore ks, String contraseña, String alias) throws IOException, KeyStoreException, NoSuchAlgorithmException {
            KeyStore.ProtectionParameter procPara = new KeyStore.PasswordProtection(contraseña.toCharArray());
            SecretKey secret = KeyGenerator.getInstance("AES" ).generateKey();
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secret);

            ks.setEntry(alias, skEntry, procPara);
            }
        public static PublicKey getPublicKey(String fitxer) throws FileNotFoundException, CertificateException {
            FileInputStream fin = new FileInputStream(fitxer);
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
            PublicKey pk = certificate.getPublicKey();

            return pk;
        }

        public static PublicKey getPublicKeyFromKeyStore(KeyStore ks, String alias) throws KeyStoreException {


            PublicKey pk = ks.getCertificate(alias).getPublicKey();
            return pk;

        }

        public static String firmar(String plainText, PrivateKey privateKey) throws Exception {
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] signature = privateSignature.sign();

            return Base64.getEncoder().encodeToString(signature);
        }


        public static boolean validar(String plaintext, PublicKey pk, String firma) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(pk);
            publicSignature.update(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] signatureBytes = Base64.getDecoder().decode(firma);

            return publicSignature.verify(signatureBytes);

        }
    }
