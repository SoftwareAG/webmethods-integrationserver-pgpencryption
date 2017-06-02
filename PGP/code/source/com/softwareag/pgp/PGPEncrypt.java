package com.softwareag.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.Stack;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

/**
 * This class provides functionality for encrypting and optionally signing data
 * using public and private keys.
 */
public class PGPEncrypt {

    /**
     * The default block size
     */
    private static final int BLOCK = 8192;

    static {
        // Initialize PGP provider
        PGPInit.init();
    }

    /**
     * Encrypts plain data from an input stream and writes cipher data to an
     * output stream. If the useArmor flag is set, the cipher data is written to
     * the output stream as an ASCII text. If not set, the output data is
     * written as raw bytes.
     * 
     * @param plain An intput stream with plain data
     * @param cipher An output stream with cipher data
     * @param key A PGP public key object
     * @param algorithm The symmetric key encryption algorithm
     * @param useArmor Flag for encoding output to ASCII
     * @throws PGPException If the message cannot be encrypted
     * @throws IOException If the streams cannot be accessed
     * @throws NoSuchProviderException If the keys or algorithms are not supported
     */
    public static void encrypt(InputStream plain, OutputStream cipher,
            PGPPublicKey key, int algorithm, boolean useArmor, String filename)
            throws PGPException, IOException, NoSuchProviderException {

        // Stream stack
        Stack<OutputStream> streams = new Stack<OutputStream>();

        // Create armored output stream
        OutputStream out = cipher;
        if (useArmor) {
            out = new ArmoredOutputStream(cipher);
        }

        // Create encrypting stream
        streams.push(out);
        PGPEncryptedDataGenerator encrypt = new PGPEncryptedDataGenerator(
                algorithm, true, new SecureRandom(), PGPInit.PROVIDER);
        encrypt.addMethod(key);
        out = encrypt.open(out, new byte[BLOCK]);

        // Create compressed stream
        streams.push(out);
        PGPCompressedDataGenerator compress = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZIP);
        out = compress.open(out);

        // Create literal stream
        streams.push(out);
        PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
        out = literal.open(out, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                plain.available(), PGPLiteralData.NOW);

        // Write plain to encrypted stream");
        byte[] buffer = new byte[BLOCK];
        while (plain.available() > 0) {
            int read = plain.read(buffer);
            out.write(buffer, 0, read);
        }

        // Close all streams
        while (!streams.isEmpty()) {
            try {
                OutputStream next = streams.pop();
                next.flush();
                next.close();
            } catch (Exception e) {
            }
        }
        cipher.flush();
    }

    /**
     * Encrypts plain data from an input stream and writes cipher data to an
     * output stream. If the useArmor flag is set, the cipher data is written to
     * the output stream as an ASCII text. If not set, the output data is
     * written as raw bytes.
     * 
     * @param plain An intput stream with plain data
     * @param cipher An output stream with cipher data
     * @param key A PGP public key object
     * @param algorithm The encryption algorithm
     * @param useArmor Flag for encoding output to ASCII
     * @param keyPrivate A private key for signing the data
     * @param password The password for the private key
     * @param hash The algorithm for signing (hash/digest)
     * @throws PGPException If the message cannot be encrypted
     * @throws IOException If the streams cannot be accessed
     * @throws NoSuchProviderException If the key types are not supported
     * @throws SignatureException If the signature cannot be created
     * @throws NoSuchAlgorithmException If the algorithms are not supported
     */
    public static void encryptAndSign(InputStream plain, OutputStream cipher,
            PGPPublicKey key, int algorithm, boolean useArmor, 
            PGPPrivateKey keyPrivate, char[] password, int hash) 
        throws PGPException, IOException, NoSuchProviderException, 
            SignatureException, NoSuchAlgorithmException {

        Stack<OutputStream> streams = new Stack<OutputStream>();

        // Create armored output stream
        OutputStream out = cipher;
        if (useArmor) {
            out = new ArmoredOutputStream(cipher);
        }

        // Create encrypting stream
        streams.push(out);
        PGPEncryptedDataGenerator encrypt = new PGPEncryptedDataGenerator(
                algorithm, true, new SecureRandom(),
                PGPInit.PROVIDER);
        encrypt.addMethod(key);
        out = encrypt.open(out, new byte[BLOCK]);

        // Set up signing
        int sign = PGPInit.getKeyExchangeAlgorithm(keyPrivate.getKey().getAlgorithm());
        PGPSignatureGenerator signer = new PGPSignatureGenerator(sign, hash,
                PGPInit.PROVIDER);
        signer.initSign(PGPSignature.BINARY_DOCUMENT, keyPrivate);
        Iterator<?> iterator = key.getUserIDs();
        if (iterator.hasNext()) {
            PGPSignatureSubpacketGenerator gen = new PGPSignatureSubpacketGenerator();
            gen.setSignerUserID(false, (String) iterator.next());
            signer.setHashedSubpackets(gen.generate());
        }

        // Create signature streams
        streams.push(out);
        PGPCompressedDataGenerator cdg = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZLIB);
        BCPGOutputStream bcp = new BCPGOutputStream(cdg.open(out));
        signer.generateOnePassVersion(false).encode(bcp);
        out = bcp;

        // Create literal stream
        streams.push(out);
        PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
        out = literal.open(out, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                plain.available(), PGPLiteralData.NOW);

        // Write plain to encrypted stream
        byte[] buffer = new byte[BLOCK];
        while (plain.available() > 0) {
            int read = plain.read(buffer);
            signer.update(buffer, 0, read);
            out.write(buffer, 0, read);
        }

        // Generating signature
        bcp.flush();
        signer.generate().encode(bcp);

        // Close all streams
        while (!streams.isEmpty()) {
            try {
                OutputStream next = streams.pop();
                next.flush();
                next.close();
            } catch (Exception e) {
            }
        }
        cipher.flush();
    }
}
