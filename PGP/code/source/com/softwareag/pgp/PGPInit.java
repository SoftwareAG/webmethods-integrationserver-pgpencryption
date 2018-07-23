/*******************************************************************************
 * /*
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
 *******************************************************************************/
package com.softwareag.pgp;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class facilitates the loading of the Bouncy Castle security provider.
 * The keyAlgorithms for cryptography and hashing listed in this class are
 * dependent on version 1.45 of the BC classes.
 * 
 * Note that the algorithms used for key-exchange (key encryption) are different
 * than those used for the actual encryption of the message (symmetric key
 * encryption). To reduce the amount of effort used to encrypt a message while
 * retaining the reliability, the message is encrypted using the symmetric
 * key algorithm and the key is encrypted with the much stronger key-exchange
 * algorithm.
 */
public class PGPInit {

    /**
     * The default security provider
     */
    public static final Provider PROVIDER = new BouncyCastleProvider();

    /**
     * List of key encryption algorithms
     */
    private static HashMap<Integer, String> keyAlgorithms = new HashMap<Integer, String>();

    /**
     * List of data encryption algorithms
     */
    private static HashMap<Integer, String> algorithms = new HashMap<Integer, String>();

    /**
     * List of hashing keyAlgorithms
     */
    private static HashMap<Integer, String> hashes = new HashMap<Integer, String>();

    /**
     * Initializes the Bouncy Castle security provider
     */
    static {

        // set default security provider
        Security.addProvider(PROVIDER);

        // Add supported key encryption keyAlgorithms
        keyAlgorithms.put(PublicKeyAlgorithmTags.DIFFIE_HELLMAN, "DH");
        keyAlgorithms.put(PublicKeyAlgorithmTags.DSA, "DSA");
        keyAlgorithms.put(PublicKeyAlgorithmTags.EC, "EC");
        keyAlgorithms.put(PublicKeyAlgorithmTags.ECDSA, "ECDSA");
        keyAlgorithms.put(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, "ELGAMAL_ENCRYPT");
        keyAlgorithms.put(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, "ELGAMAL");
        keyAlgorithms.put(PublicKeyAlgorithmTags.RSA_ENCRYPT, "RSA_ENCRYPT");
        keyAlgorithms.put(PublicKeyAlgorithmTags.RSA_GENERAL, "RSA");
        keyAlgorithms.put(PublicKeyAlgorithmTags.RSA_SIGN, "RSA_SIGN");

        // Add supported symmetric key keyAlgorithms
        algorithms.put(SymmetricKeyAlgorithmTags.AES_128, "AES_128");
        algorithms.put(SymmetricKeyAlgorithmTags.AES_192, "AES_192");
        algorithms.put(SymmetricKeyAlgorithmTags.AES_256, "AES_256");
        algorithms.put(SymmetricKeyAlgorithmTags.BLOWFISH, "BLOWFISH");
        algorithms.put(SymmetricKeyAlgorithmTags.CAST5, "CAST5");
        algorithms.put(SymmetricKeyAlgorithmTags.DES, "DES");
        algorithms.put(SymmetricKeyAlgorithmTags.IDEA, "IDEA");
        algorithms.put(SymmetricKeyAlgorithmTags.SAFER, "SAFER");
        algorithms.put(SymmetricKeyAlgorithmTags.TRIPLE_DES, "TRIPLE_DES");
        algorithms.put(SymmetricKeyAlgorithmTags.TWOFISH, "TWOFISH");

        // Add supported hashing keyAlgorithms
        hashes.put(HashAlgorithmTags.DOUBLE_SHA, "DOUBLE_SHA");
        hashes.put(HashAlgorithmTags.HAVAL_5_160, "HAVAL_5_160");
        hashes.put(HashAlgorithmTags.MD2, "MD2");
        hashes.put(HashAlgorithmTags.MD5, "MD5");
        hashes.put(HashAlgorithmTags.RIPEMD160, "RIPEMD160");
        hashes.put(HashAlgorithmTags.SHA1, "SHA1");
        hashes.put(HashAlgorithmTags.SHA224, "SHA224");
        hashes.put(HashAlgorithmTags.SHA256, "SHA256");
        hashes.put(HashAlgorithmTags.SHA384, "SHA384");
        hashes.put(HashAlgorithmTags.SHA512, "SHA512");
        hashes.put(HashAlgorithmTags.TIGER_192, "TIGER 192");
    }
    
    /**
     * Initializes this class
     */
    public final static void init() {
        
    }

    /**
     * Returns the name of a key algorithm
     * 
     * @param i The constant algorithm code
     * @return The name of the algorithm
     */
    public static String getKeyExchangeAlgorithm(int i) {

        String algorithm = null;
        if (keyAlgorithms.containsKey(i)) {
            algorithm = keyAlgorithms.get(i);
        } else {
            throw new IllegalArgumentException(
                    "Key encryption algorithm not supported: " + i);
        }
        return algorithm;
    }

    /**
     * Returns the numeric identifier of a key algorithm
     * 
     * @param name The constant algorithm name
     * @return The identifier
     */
    public static int getKeyExchangeAlgorithm(String name) {

        int algorithm = 0;
        if (keyAlgorithms.containsValue(name)) {
            for (Iterator<Integer> i = keyAlgorithms.keySet().iterator(); i
                    .hasNext();) {
                int key = i.next();
                if (name.equals(keyAlgorithms.get(key))) {
                    algorithm = key;
                }
            }
        } else {
            throw new IllegalArgumentException(
                    "Key encryption algorithm not supported: " + name);
        }
        return algorithm;
    }

    /**
     * Returns the name of an algorithm
     * 
     * @param name The constant algorithm code
     * @return The name of the algorithm
     */
    public static String getAlgorithm(int name) {

        String algorithm = null;
        if (algorithms.containsKey(name)) {
            algorithm = algorithms.get(name);
        } else {
            throw new IllegalArgumentException(
                    "Encryption algorithm not supported: " + name);
        }
        return algorithm;
    }

    /**
     * Returns the numeric identifier of an algorithm
     * 
     * @param name The constant algorithm name
     * @return The identifier
     */
    public static int getAlgorithm(String name) {

        int algorithm = 0;
        if (algorithms.containsValue(name)) {
            for (Iterator<Integer> i = algorithms.keySet().iterator(); i
                    .hasNext();) {
                int key = i.next();
                if (name.equals(algorithms.get(key))) {
                    algorithm = key;
                }
            }
        } else {
            throw new IllegalArgumentException(
                    "Encryption algorithm not supported: " + name);
        }
        return algorithm;
    }
    
    /**
     * Returns the name of a hash algorithm
     * 
     * @param i The constant hash code
     * @return The name of the hash
     */
    public static String getHashAlgorithm(int i) {

        String hash = null;
        if (hashes.containsKey(i)) {
            hash = hashes.get(i);
        } else {
            throw new IllegalArgumentException(
                    "Hashing algorithm not supported: " + i);
        }
        return hash;
    }

    /**
     * Returns the numeric identifier of a key hash
     * 
     * @param name The constant hash name
     * @return The identifier
     */
    public static int getHashAlgorithm(String name) {

        int hash = 0;
        if (hashes.containsValue(name)) {
            for (Iterator<Integer> i = hashes.keySet().iterator(); i.hasNext();) {
                int key = i.next();
                if (name.equals(hashes.get(key))) {
                    hash = key;
                }
            }
        } else {
            throw new IllegalArgumentException(
                    "Hashing algorithm not supported: " + name);
        }
        return hash;
    }
    
    /**
     * Returns all key exchange algorithms
     * @return A list of algorithm names
     */
    public static ArrayList<String> listKeyExchangeAlgorithms() {
        
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(keyAlgorithms.values());
        return list;
    }

    /**
     * Returns all encryption algorithms
     * @return A list of algorithm names
     */
    public static ArrayList<String> listEncryptionAlgorithms() {
        
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(algorithms.values());
        return list;
    }

    /**
     * Returns all signing algorithms
     * @return A list of algorithm names
     */
    public static ArrayList<String> listSignatureAlgorithms() {
        
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(hashes.values());
        return list;
    }
}