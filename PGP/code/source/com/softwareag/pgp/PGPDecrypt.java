package com.softwareag.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Iterator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * This class provides functionality for decrypting and optionally verifying
 * encrypted data using public and private keys.
 */
public class PGPDecrypt {


    static {
        // Initialize PGP provider
        PGPInit.init();
    }

    /**
     * Decrypts cipher data from an input stream and writes plain data to an
     * output stream. Based on the identifier included in the cipher data, the
     * suitable private key will extracted from the secret key ring. Note that
     * the plain data in the output stream is in bytes and that any character
     * set encoding needs to be applied if necessary.
     * 
     * @param cipher An input stream with cipher data
     * @param plain An output stream with plain data
     * @param ringSecret A secret key ring collection
     * @param password A password for the private key
     * @throws PGPException If the message cannot be decrypted
     * @throws IOException If the streams cannot be accessed
     * @throws NoSuchProviderException If the key types are not supported
     */
    public static void decrypt(InputStream cipher, OutputStream plain,
            PGPSecretKeyRingCollection ringSecret, char[] password)
            throws PGPException, IOException, NoSuchProviderException {

        // Decode inputstream
        cipher = PGPUtil.getDecoderStream(cipher);

        // Find encrypted objects
        PGPObjectFactory factory = new PGPObjectFactory(cipher);
        PGPEncryptedDataList encrypted = null;
        Object object = factory.nextObject();
        if (PGPEncryptedDataList.class.isAssignableFrom(object.getClass())) {
            encrypted = (PGPEncryptedDataList) object;
        } else {
            encrypted = (PGPEncryptedDataList) factory.nextObject();
        }
        if (encrypted == null) {
            throw new PGPException("Invalid cipher data");
        }

        // Find encrypted data
        PGPPublicKeyEncryptedData pbe = null;
        PGPPrivateKey key = null;
        for (Iterator<?> i = encrypted.getEncryptedDataObjects(); i.hasNext();) {
            object = i.next();
            if (PGPPublicKeyEncryptedData.class.isAssignableFrom(object
                    .getClass())) {
                pbe = (PGPPublicKeyEncryptedData) object;
                PGPSecretKey secret = ringSecret.getSecretKey(pbe.getKeyID());
                if (secret != null) {
                    key = secret.extractPrivateKey(password, PGPInit.PROVIDER);
                } else {
                    throw new PGPException("Private key not found");
                }
                break;
            }
        }
        if (pbe == null) {
            throw new PGPException("No cipher data available");
        }
        if (key == null) {
            throw new PGPException("Private key not valid");
        }

        // Get encrypted data
        InputStream clear = pbe.getDataStream(key, PGPInit.PROVIDER.getName());
        factory = new PGPObjectFactory(clear);
        PGPCompressedData compressed = null;
        while ((object = factory.nextObject()) != null) {
            if (PGPCompressedData.class.isAssignableFrom(object.getClass())) {
                compressed = (PGPCompressedData) object;
                break;
            }
        }

        factory = new PGPObjectFactory(compressed.getDataStream());
        PGPLiteralData literal = null;
        while ((object = factory.nextObject()) != null) {
            if (PGPLiteralData.class.isAssignableFrom(object.getClass())) {
                literal = (PGPLiteralData) object;
                break;
            }
        }
        clear = literal.getInputStream();

        // Write decrypted data
        byte[] buffer = new byte[512];
        int read = 0;
        while ((read = clear.read(buffer)) > 0) {
            plain.write(buffer, 0, read);
        }
        plain.flush();
    }

    /**
     * Decrypts cipher data from an input stream and writes plain data to an
     * output stream. Based on the identifier included in the cipher data, the
     * suitable public key will be extracted from the public key ring for 
     * verification of the signature and the suitable private key will extracted 
     * from the secret key ring for decryption. Note that
     * the plain data in the output stream is in bytes and that any character
     * set encoding needs to be applied if necessary.
     * 
     * @param cipher An input stream with cipher data
     * @param plain An output stream with plain data
     * @param ringPub A public key ring collection
     * @param ringSecret A secret key ring collection
     * @param password A password for the private key
     * @throws PGPException If the message cannot be decrypted
     * @throws IOException If the streams cannot be accessed
     * @throws NoSuchProviderException If the key types are not supported
     */
    public static int decryptAndVerify(InputStream cipher, OutputStream plain,
            PGPSecretKeyRingCollection ringSecret, char[] password, 
            PGPPublicKeyRingCollection ringPub)
            throws PGPException, IOException, NoSuchProviderException {

        // Decode inputstream
        cipher = PGPUtil.getDecoderStream(cipher);

        // Find encrypted objects
        PGPObjectFactory factory = new PGPObjectFactory(cipher);
        PGPEncryptedDataList encrypted = null;
        Object object = null;
        while ((object = factory.nextObject()) != null) {
            if (PGPEncryptedDataList.class.isAssignableFrom(object.getClass())) {
                encrypted = (PGPEncryptedDataList) object;
                break;
            }
        }
        if (encrypted == null) {
            throw new PGPException("Invalid cipher data");
        }

        // Find encrypted data
        PGPPublicKeyEncryptedData pbe = null;
        PGPPrivateKey key = null;
        for (Iterator<?> i = encrypted.getEncryptedDataObjects(); i.hasNext();) {
            object = i.next();
            if (PGPPublicKeyEncryptedData.class.isAssignableFrom(object
                    .getClass())) {
                pbe = (PGPPublicKeyEncryptedData) object;
                PGPSecretKey secret = ringSecret.getSecretKey(pbe.getKeyID());
                if (secret != null) {
                    key = secret.extractPrivateKey(password, PGPInit.PROVIDER);
                } else {
                    throw new PGPException("Private key not found");
                }
                break;
            }
        }
        if (pbe == null) {
            throw new PGPException("No cipher data available");
        }
        if (key == null) {
            throw new PGPException("Private key not valid");
        }

        // Get encrypted data
        InputStream clear = pbe.getDataStream(key, PGPInit.PROVIDER.getName());
        factory = new PGPObjectFactory(clear);
        PGPCompressedData compressed = null;
        while ((object = factory.nextObject()) != null) {
            if (PGPCompressedData.class.isAssignableFrom(object.getClass())) {
                compressed = (PGPCompressedData) object;
                break;
            }
        }

        int verified = 0;
        
        factory = new PGPObjectFactory(compressed.getDataStream());
        PGPLiteralData literal = null;
        PGPOnePassSignatureList signatures = null;
        PGPOnePassSignature ops = null;
        PGPPublicKey pubKey = null;
        while ((object = factory.nextObject()) != null) {
            if (PGPOnePassSignatureList.class.isAssignableFrom(object
                    .getClass())) {
                // Verify signature
                signatures = (PGPOnePassSignatureList) object;
                ops = signatures.get(0);
                pubKey = ringPub.getPublicKey(ops.getKeyID());
                ops.initVerify(pubKey, PGPInit.PROVIDER);
            } else if (PGPLiteralData.class.isAssignableFrom(object.getClass())) {
                literal = (PGPLiteralData) object;
                clear = literal.getInputStream();

                // Write decrypted data
                try {
                    byte[] buffer = new byte[8192];
                    int read = 0;
                    while ((read = clear.read(buffer)) > 0) {
                        plain.write(buffer, 0, read);
                        if (ops != null) {
                            ops.update(buffer, 0, read);
                        }
                    }
                    if (ops != null) {
                        if (ops.verify(((PGPSignatureList)factory.nextObject()).get(0))) {
                            verified = 1;
                        } else {
                            verified = -1;
                        }
                    } else {
                        verified = 0;
                    }
                } catch (SignatureException se) {
                    se.printStackTrace();
                }
            } else {
            }
        }

        plain.flush();
        return verified;
    }
}
