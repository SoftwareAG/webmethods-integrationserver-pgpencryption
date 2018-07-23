/*
 * * Copyright ©  2018 Software AG, Darmstadt, Germany and/or its licensors
 * *
 * * SPDX-License-Identifier: Apache-2.0
 * *
 * * Licensed under the Apache License, Version 2.0 (the "License");
 * * you may not use this file except in compliance with the License.
 * * You may obtain a copy of the License at
 * *
 * * http://www.apache.org/licenses/LICENSE-2.0
 * *
 * *  Unless required by applicable law or agreed to in writing, software
 * *  distributed under the License is distributed on an "AS IS" BASIS,
 * *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * *  See the License for the specific language governing permissions and
 * *  limitations under the License.                                                            
 * *
 * */
package com.softwareag.pgp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * This class provides keys for accessing public and private key data. 
 */
public class PGPKeyReader {
	
    
    public static PGPPublicKeyRingCollection readPublicKeyRing(String path) 
        throws IOException, PGPException {
    
        PGPPublicKeyRingCollection coll = null;
        InputStream in = null;
        try {
            // Access file as stream
            in = new FileInputStream(new File(path));
    
            // Get the decoder stream (auto-disarming)
            in = PGPUtil.getDecoderStream(in);
    
            // Open the key ring
            coll = new PGPPublicKeyRingCollection(in);
        } catch (IOException ioe) {
            //logger.error(ioe.getMessage());
            throw ioe;
        } catch (PGPException pgpe) {
            //logger.error(pgpe.getMessage());
            throw pgpe;
        } finally {
            try {
                in.close();
            } catch (Exception e) {
            }
        }
        return coll;
    }

    public static PGPPublicKey readPublicKey(String path, int algorithm)
            throws IOException, PGPException {

        PGPPublicKey key = null;
        FileInputStream in = null;
        try {
            // Access file as stream
            in = new FileInputStream(new File(path));
            key = PGPKeyReader.readPublicKey(in, algorithm);
        } catch (IOException ioe) {
            //logger.error(ioe.getMessage());
            throw ioe;
        } catch (PGPException pgpe) {
            //logger.error(pgpe.getMessage());
            throw pgpe;
        } finally {
            try {
                in.close();
            } catch (Exception e) {
            }
        }
        return key;
    }

    public static PGPPublicKey readPublicKey(InputStream in, int algorithm)
            throws IOException, PGPException {

        // Get the decoder stream (auto-disarming)
        in = PGPUtil.getDecoderStream(in);

        // Open the key ring
        PGPPublicKeyRingCollection coll = new PGPPublicKeyRingCollection(in);

        // Find key encryption key for algorithm, if given
        return readPublicKey(coll, algorithm);
    }
    
    public static PGPPublicKey readPublicKey(PGPPublicKeyRingCollection coll, int algorithm) 
        throws IOException, PGPException {

        ArrayList<String> others = new ArrayList<String>();
        PGPPublicKey key = null;
        main: for (Iterator<?> i = coll.getKeyRings(); i.hasNext();) {
            PGPPublicKeyRing ring = (PGPPublicKeyRing) i.next();
            for (Iterator<?> j = ring.getPublicKeys(); j.hasNext();) {
                PGPPublicKey next = (PGPPublicKey) j.next();
                //logger.debug("Found public key: " 
                //        + PGPInit.getKeyExchangeAlgorithm(next.getAlgorithm()));
                if (next.isEncryptionKey()
                        && (next.getAlgorithm() == algorithm || algorithm == 0)) {
                    key = next;
                    break main;
                } else {
                    others.add(PGPInit.getKeyExchangeAlgorithm(next.getAlgorithm()));
                }
            }
        }
        
        // If not found, throw error
        if (key == null) {
            if (others.size() > 0) {
                StringBuffer buffer = new StringBuffer();
                String sep = "";
                for (int i = 0; i < others.size(); i++) {
                    buffer.append(sep).append(others.get(i));
                    sep = ", ";
                }
                throw new PGPException("Public key not found; Choose algorithm from " + buffer.toString());
            } else {
                throw new PGPException("Public key not found");
            }
        }
        return key;
    }

    public static PGPSecretKeyRingCollection readSecretKeyRing(String path) 
        throws IOException, PGPException {

        PGPSecretKeyRingCollection coll = null;
        InputStream in = null;
        try {
            // Access file as stream
            in = new FileInputStream(new File(path));

            // Get the decoder stream (auto-disarming)
            in = PGPUtil.getDecoderStream(in);

            // Open the key ring
            coll = new PGPSecretKeyRingCollection(in);
        } catch (IOException ioe) {
            //logger.error(ioe.getMessage());
            throw ioe;
        } catch (PGPException pgpe) {
            //logger.error(pgpe.getMessage());
            throw pgpe;
        } finally {
            try {
                in.close();
            } catch (Exception e) {
            }
        }
        return coll;
    }
    
    public static PGPSecretKey readSecretKey(String path)
            throws IOException, PGPException, NoSuchProviderException {

        PGPSecretKey key = null;
        FileInputStream in = null;
        try {
            // Access file as stream
            in = new FileInputStream(new File(path));
            key = PGPKeyReader.readSecretKey(in);
        } catch (IOException ioe) {
            //logger.error(ioe.getMessage());
            throw ioe;
        } catch (PGPException pgpe) {
            //logger.error(pgpe.getMessage());
            throw pgpe;
        } finally {
            try {
                in.close();
            } catch (Exception e) {
            }
        }
        return key;
    }

    public static PGPSecretKey readSecretKey(InputStream in)
            throws IOException, PGPException, NoSuchProviderException {

        // Get the decoder stream (auto-disarming)
        in = PGPUtil.getDecoderStream(in);

        // Open the key ring
        PGPSecretKeyRingCollection coll = new PGPSecretKeyRingCollection(in);

        // Find key
        return readSecretKey(coll);
    }

    public static PGPSecretKey readSecretKey(PGPSecretKeyRingCollection secret)
            throws PGPException, NoSuchProviderException {
        
        PGPSecretKey key = null;
        main: for (Iterator<?> i = secret.getKeyRings(); i.hasNext();) {
            PGPSecretKeyRing ring = (PGPSecretKeyRing) i.next();
            for (Iterator<?> j = ring.getSecretKeys(); j.hasNext();) {
                PGPSecretKey next = (PGPSecretKey) j.next();
                //logger.debug("Found secret key: "
                //        + PGPInit.getKeyExchangeAlgorithm(next
                //                .getKeyEncryptionAlgorithm()));
                if (next.isSigningKey()) {
                    key = next;
                    break main;
                }
            }
        }

        // If not found, throw error
        if (key == null) {
            throw new PGPException("Secret key not found");
        }

        return key;
    }

    public static PGPPrivateKey readPrivateKey(PGPSecretKey secret, char[] pass)
            throws PGPException, NoSuchProviderException {

        PGPPrivateKey key = null;
        try {
            key = secret.extractPrivateKey(pass, PGPInit.PROVIDER.getName());
        } catch (PGPException pgpe) {
            if (pgpe.getMessage().indexOf("checksum mismatch") >= 0) {
                throw new PGPException("Private key password invalid");
            } else {
                throw pgpe;
            }
        }
        return key;
    }

    public static String getKeyInfo(PGPPublicKeyRingCollection coll) {
        
        StringBuffer info = new StringBuffer();
        
        // Iterate through key rings
        Iterator<?> rings = coll.getKeyRings();
        while (rings.hasNext()) {
            PGPPublicKeyRing ring = (PGPPublicKeyRing)rings.next();
            Iterator<?> keys = ring.getPublicKeys();
            while (keys.hasNext()) {
                info.append(getKeyInfo((PGPPublicKey)keys.next())).append("\n");
            }
        }
        return info.toString();
    }
    
    /**
     * Returns information on a public key
     * @param key A PGP public key
     * @return Key information
     */
    public static String getKeyInfo(PGPPublicKey key) {
        
        StringBuffer info = new StringBuffer(PGPInit.getKeyExchangeAlgorithm(key.getAlgorithm()))
            .append(" (").append(key.getBitStrength()).append(")")
            .append(" v").append(key.getVersion())
            .append(" id:").append(key.getKeyID())
            .append(" ").append(key.getCreationTime());
        if (key.isEncryptionKey()) {
            info.append(" [").append("encryption").append("]");
        }
        if (key.isMasterKey()) {
            info.append(" [").append("master").append("]");
        }
        if (key.isRevoked()) {
            info.append(" [").append("revoked").append("]");
        }
        
        return info.toString();
    }

    public static String getKeyInfo(PGPSecretKeyRingCollection coll) {
        
        StringBuffer info = new StringBuffer();
        
        // Iterate through key rings
        Iterator<?> rings = coll.getKeyRings();
        while (rings.hasNext()) {
            PGPSecretKeyRing ring = (PGPSecretKeyRing)rings.next();
            Iterator<?> keys = ring.getSecretKeys();
            while (keys.hasNext()) {
                info.append(getKeyInfo((PGPSecretKey)keys.next())).append("\n");
            }
        }
        return info.toString();
    }

    /**
     * Returns information on a secret key
     * @param secret A PGP secret key
     * @return Key information
     */
    public static String getKeyInfo(PGPSecretKey secret) {
        
        StringBuffer info = new StringBuffer(PGPInit.getKeyExchangeAlgorithm(secret.getPublicKey().getAlgorithm()))
            .append(" (").append(secret.getPublicKey().getBitStrength()).append(")")
            .append(" id:").append(secret.getKeyID());
        if (secret.isMasterKey()) {
            info.append(" [").append("master").append("]");
        }
        if (secret.isSigningKey()) {
            info.append(" [").append("signer").append("]");
        }
        
        return info.toString();
    }

    /**
     * Returns information on a secret and private key
     * @param key A PGP private key
     * @return Key information
     */
    public static String getKeyInfo(PGPPrivateKey key) {
        
        StringBuffer info = new StringBuffer(PGPInit.getKeyExchangeAlgorithm(key.getKey().getAlgorithm()))
            .append(" (").append(key.getKey().getFormat()).append(")")
            .append(" id:").append(key.getKeyID());
        
        return info.toString();
    }
}
