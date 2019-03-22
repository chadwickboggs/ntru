package ntru; /******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/

import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * This class is sample code for the jNeo toolkit. It supports 3
 * operations:
 * <ul>creating an NtruEncrypt key
 * <ul>encrypting a file with a dynamically-generated AES key and wrapping
 * (encrypting) the AES key with an NtruEncrypt key.
 * <ul>decrypting an encrypted file.
 */
public class Sample {

    /**
     * Creates a public/private key pair and saves the two components
     * to disk.
     *
     * @param prng         the source of randomness to use during key creation.
     * @param oid          identifies the NtruEncrypt parameter set to use.
     * @param pubFileName  where to store the public key.
     * @param privFileName where to store the private key.
     */
    public static void setupNtruEncryptKey(
        Random prng,
        OID oid,
        String pubFileName,
        String privFileName
    ) throws IOException, NtruException {

        NtruEncryptKey k = NtruEncryptKey.genKey(oid, prng);

        FileOutputStream pubFile = new FileOutputStream(pubFileName);
        pubFile.write(k.getPubKey());
        pubFile.close();

        FileOutputStream privFile = new FileOutputStream(privFileName);
        privFile.write(k.getPrivKey());
        privFile.close();
    }


    /**
     * Load a public or private NtruEncrypt key blob from disk and instantiate
     * an NtruEncryptKey object from it.
     */
    public static NtruEncryptKey loadKey(
        String keyFileName
    ) throws IOException, NtruException {

        // Get the file length
        File keyFile = new File(keyFileName);
        long fileLength = keyFile.length();
        if (fileLength > Integer.MAX_VALUE)
            throw new IOException("file to be encrypted is too large");

        // Load the bytes from the file, instantiate an NtruEncryptKey object,
        // then clean up and return.
        InputStream in = new FileInputStream(keyFile);
        byte buf[] = new byte[(int) fileLength];
        in.read(buf);
        in.close();
        NtruEncryptKey k = new NtruEncryptKey(buf);
        java.util.Arrays.fill(buf, (byte) 0);
        return k;
    }


    /**
     * Encrypt a file, protecting it using the supplied NtruEncrypt key.
     *
     * <p>This method actually performs two levels of encryption.
     * First, the file contents are encrypted using a
     * dynamically-generated AES-256 key in CCM mode. Then the AES key
     * is encrypted with the supplied NtruEncrypt key. The two encrypted
     * blobs, as well as any other non-sensitive data needed for decryption,
     * are writen to disk as "filename.enc".
     *
     * @param ntruKey  the NtruEncrypt key to use to wrap the AES key.
     * @param prng     the source of randomness used during the NtruEncrypt
     *                 operation and to generate the AES key.
     */
    public static void encryptFile(
        NtruEncryptKey ntruKey,
        Random prng,
        String inFileName,
        String outFileName
    ) throws IOException, NtruException {

        // Get the input size
        File inFile = new File(inFileName);
        long fileLength = inFile.length();
        if (fileLength > Integer.MAX_VALUE)
            throw new IOException("file to be encrypted is too large");

        // Read the contents of the file
        InputStream in = new FileInputStream(inFile);
        byte buf[] = new byte[(int) fileLength];
        in.read(buf);
        in.close();

        byte ivBytes[] = null;
        byte encryptedBuf[] = null;
        byte wrappedAESKey[] = null;
        try {
            // Get an AES key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            SecretKey aesKey = keygen.generateKey();

            // Get an IV
            ivBytes = new byte[16];
            prng.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Encrypt the plaintext, then zero it out
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            encryptedBuf = cipher.doFinal(buf);
            java.util.Arrays.fill(buf, (byte) 0);

            // Wrap the AES key with the NtruEncrypt key
            byte aesKeyBytes[] = aesKey.getEncoded();
            wrappedAESKey = ntruKey.encrypt(aesKeyBytes, prng);
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

        }
        catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        // Write it to the output file
        FileOutputStream fileOS = new FileOutputStream(outFileName);
        DataOutputStream out = new DataOutputStream(fileOS);
        out.writeInt(ivBytes.length);
        out.write(ivBytes);
        out.writeInt(wrappedAESKey.length);
        out.write(wrappedAESKey);
        out.writeInt(encryptedBuf.length);
        out.write(encryptedBuf);
        out.close();
        fileOS.close();
    }


    public static byte[] encryptByteArray(
        final NtruEncryptKey ntruKey,
        final Random prng,
        final byte[] sourceBytes
    ) throws IOException, NtruException {

        byte ivBytes[] = null;
        byte encryptedBuf[] = null;
        byte wrappedAESKey[] = null;
        try {
            // Get an AES key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            SecretKey aesKey = keygen.generateKey();

            // Get an IV
            ivBytes = new byte[16];
            prng.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Encrypt the plaintext, then zero it out
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            encryptedBuf = cipher.doFinal(sourceBytes);
            java.util.Arrays.fill(sourceBytes, (byte) 0);

            // Wrap the AES key with the NtruEncrypt key
            byte aesKeyBytes[] = aesKey.getEncoded();
            wrappedAESKey = ntruKey.encrypt(aesKeyBytes, prng);
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

        }
        catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        // Write it to the output file
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(byteArrayOutputStream);
        out.writeInt(ivBytes.length);
        out.write(ivBytes);
        out.writeInt(wrappedAESKey.length);
        out.write(wrappedAESKey);
        out.writeInt(encryptedBuf.length);
        out.write(encryptedBuf);
        out.close();

        return byteArrayOutputStream.toByteArray();
    }


    /**
     * Decrypt a file, reversing the <code>encryptFile</code> operation.
     */
    public static void decryptFile(
        NtruEncryptKey ntruKey,
        String inFileName,
        String outFileName
    ) throws IOException, NtruException {

        // Get the input size
        File inFile = new File(inFileName);
        long fileLength = inFile.length();

        // Parse the contents of the encrypted file
        DataInputStream in = new DataInputStream(new FileInputStream(inFile));
        byte ivBytes[] = new byte[in.readInt()];
        in.readFully(ivBytes);
        byte wrappedKey[] = new byte[in.readInt()];
        in.readFully(wrappedKey);
        byte encFileContents[] = new byte[in.readInt()];
        in.readFully(encFileContents);

        byte fileContents[] = null;
        try {
            // Unwrap the AES key
            byte aesKeyBytes[] = ntruKey.decrypt(wrappedKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

            // Decrypt the file contents
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            fileContents = cipher.doFinal(encFileContents);
        }
        catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        // Write it
        OutputStream out = new FileOutputStream(outFileName);
        out.write(fileContents);
        out.close();
    }


    public static byte[] decryptByteArray(
        final NtruEncryptKey ntruKey,
        final byte[] sourceBytes
    ) throws IOException, NtruException {

        // Parse the contents of the encrypted file
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(sourceBytes));
        byte[] ivBytes = new byte[in.readInt()];
        in.readFully(ivBytes);
        byte[] wrappedKey = new byte[in.readInt()];
        in.readFully(wrappedKey);
        byte[] encFileContents = new byte[in.readInt()];
        in.readFully(encFileContents);

        byte[] fileContents = null;
        try {
            // Unwrap the AES key
            byte[] aesKeyBytes = ntruKey.decrypt(wrappedKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

            // Decrypt the file contents
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            fileContents = cipher.doFinal(encFileContents);
        }
        catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        return fileContents;
    }


    public static void encryptStream(
        final NtruEncryptKey ntruKey,
        final Random prng,
        final InputStream inputStream,
        final OutputStream outputStream
    ) throws IOException, NtruException {

        List<Byte> byteList = new ArrayList<>();
        byte[] oneByte = new byte[1];
        while (inputStream.available() > 0) {
            if (inputStream.read(oneByte) <= 0) {
                outputStream.flush();

                return;
            }

            byteList.add(oneByte[0]);
        }
        int byteCount = byteList.size();
        Byte[] bytesObjectsRead = new Byte[byteCount];
        byte[] bytesRead = new byte[byteCount];
        byteList.toArray(bytesObjectsRead);
        for (int i = 0; i < bytesObjectsRead.length; i++) {
            Byte byteObject = bytesObjectsRead[i];
            bytesRead[i] = byteObject.byteValue();
        }

        byte[] ivBytes = null;
        byte[] encryptedBuf = null;
        byte[] wrappedAESKey = null;
        try {
            // Get an AES key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            SecretKey aesKey = keygen.generateKey();

            // Get an IV
            ivBytes = new byte[16];
            prng.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Encrypt the plaintext, then zero it out
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            encryptedBuf = cipher.doFinal(bytesRead);
            java.util.Arrays.fill(bytesRead, (byte) 0);

            // Wrap the AES key with the NtruEncrypt key
            byte[] aesKeyBytes = aesKey.getEncoded();
            wrappedAESKey = ntruKey.encrypt(aesKeyBytes, prng);
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

        }
        catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        DataOutputStream out = new DataOutputStream(outputStream);
        out.writeInt(ivBytes.length);
        out.write(ivBytes);
        out.writeInt(wrappedAESKey.length);
        out.write(wrappedAESKey);
        out.writeInt(encryptedBuf.length);
        out.write(encryptedBuf);
        out.flush();
    }


    public static void decryptStream(
        final NtruEncryptKey ntruKey,
        final InputStream inputStream,
        final OutputStream outputStream
    ) throws IOException, NtruException {

        DataInputStream in = new DataInputStream(inputStream);
        byte[] ivBytes = new byte[in.readInt()];
        in.readFully(ivBytes);
        byte[] wrappedKey = new byte[in.readInt()];
        in.readFully(wrappedKey);
        byte[] encFileContents = new byte[in.readInt()];
        in.readFully(encFileContents);

        byte[] fileContents = null;
        try {
            // Unwrap the AES key
            byte[] aesKeyBytes = ntruKey.decrypt(wrappedKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

            // Decrypt the file contents
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            fileContents = cipher.doFinal(encFileContents);
        }
        catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        // Write it
        outputStream.write(fileContents);
        outputStream.flush();
    }


    /**
     * Creates a com.securityinnovation.jNeo.Random object seeded with entropy from
     * java.util.Random.
     */
    public static Random createSeededRandom() {
        byte seed[] = new byte[32];
        java.util.Random sysRand = new java.util.Random();
        sysRand.nextBytes(seed);
        Random prng = new Random(seed);
        return prng;
    }


    /**
     * Print usage information and exit indicating an error.
     */
    static void usage() {
        System.out.println("Arguments:");
        System.out.println("  -setup <oidName>");
        System.out.println("  -encrypt <inFileName> <outFileName>");
        System.out.println("  -decrypt <inFileName> <outFileName>");
        System.exit(1);
    }


    /**
     * Given a string containing the name of an OID (e.g. "ees401ep1"),
     * return the OID enum with that name. If there is no OID,
     * exit with an informative message.
     */
    static OID parseOIDName(
        String requestedOid) {
        try {
            return OID.valueOf(requestedOid);
        }
        catch (IllegalArgumentException e) {
            System.out.println("Invalid OID! Valid values are:");
            for (OID oid : OID.values())
                System.out.println("  " + oid);
            System.exit(1);
        }
        return null;
    }


    public static void main(String[] args)
        throws IOException, NtruException {
        if (args.length == 0)
            usage();

        // Standard key file names.
        String pubkeyFile = "pubKey";
        String privkeyFile = "privKey";

        if (args[0].equals("-setup")) {
            if (args.length != 2) usage();

            setup(args[1], pubkeyFile, privkeyFile);
        }
        else if (args[0].equals("-encrypt")) {
            if (args.length != 3) usage();

            encrypt(args, pubkeyFile);
        }
        else if (args[0].equals("-decrypt")) {
            if (args.length != 3) usage();

            decrypt(args, privkeyFile);
        }
        else
            usage();
    }


    public static void setup(
        final String oidName, final String pubkeyFile, final String privkeyFile
    ) throws IOException, NtruException {

        Random prng = createSeededRandom();
        OID oid = parseOIDName(oidName);

        setupNtruEncryptKey(prng, oid, pubkeyFile, privkeyFile);
    }


    public static void encrypt(
        final String[] args, final String pubkeyFile
    ) throws IOException, NtruException {

        Random prng = createSeededRandom();
        NtruEncryptKey pubKey = loadKey(pubkeyFile);

        encryptFile(pubKey, prng, args[1], args[2]);
    }


    public static void decrypt(
        final String[] args,
        final String privkeyFile
    ) throws IOException, NtruException {

        NtruEncryptKey privKey = loadKey(privkeyFile);

        decryptFile(privKey, args[1], args[2]);
    }
}
