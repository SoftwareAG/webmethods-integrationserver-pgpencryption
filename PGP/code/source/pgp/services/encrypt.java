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
 *******************************************************************************/
package pgp.services;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import com.softwareag.pgp.PGPEncrypt;
import com.softwareag.pgp.PGPInit;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataUtil;
// --- <<IS-END-IMPORTS>> ---

public final class encrypt

{
	// ---( internal utility methods )---

	final static encrypt _instance = new encrypt();

	static encrypt _newInstance() { return new encrypt(); }

	static encrypt _cast(Object o) { return (encrypt)o; }

	// ---( server methods )---




	public static final void encryptAndSign (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(encryptAndSign)>> ---
		// @specification pgp.specifications:encryptAndSignSpec
		// @subtype unknown
		// @sigtype java 3.5
		// Get plain text input
		IDataCursor pc = pipeline.getCursor();
		String plainTextPath = IDataUtil.getString(pc, "plainTextPath");
		byte[] plainTextBytes = (byte[])IDataUtil.get(pc, "plainTextBytes");
		String plainTextString = IDataUtil.getString(pc, "plainTextString");
		InputStream plainTextStream = (InputStream)IDataUtil.get(pc, "plainTextStream");
		String plainTextEncoding = IDataUtil.getString(pc, "plainTextEncoding");
		
		// Validate plain text input
		boolean autoClose = false;
		try {
		    if (plainTextPath != null && !plainTextPath.equals("")) {
		        plainTextStream = new FileInputStream(new File(plainTextPath));
		        autoClose = true;
		    } else if (plainTextBytes != null && plainTextBytes.length > 0) {
		        plainTextStream = new ByteArrayInputStream(plainTextBytes);
		        autoClose = true;
		    } else if (plainTextString != null && !plainTextString.equals("")) {
		        plainTextStream = new ByteArrayInputStream(
		                plainTextString.getBytes(plainTextEncoding));
		        autoClose = true;
		    } else {
		        // Throws an exception if unavailable
		        plainTextStream.available();
		    } 
		} catch (FileNotFoundException fnfe) {
		    throw new ServiceException("Plain text file was not found");
		} catch (UnsupportedEncodingException uee) {
		    throw new ServiceException("Plain text encoding is invalid");
		} catch (IOException ioe) {
		    throw new ServiceException("Plain text stream is empty");
		} catch (NullPointerException npe) {
		    throw new ServiceException("No plain data available");
		}
		if (plainTextEncoding == null || plainTextEncoding.equals("")) {
		    plainTextEncoding = "UTF-8";
		} else if (!Charset.isSupported(plainTextEncoding)) {
		    throw new ServiceException("Unsupported character encoding");
		}
		
		// Get key input
		PGPPublicKey publicKey = (PGPPublicKey) IDataUtil.get(pc, "publicKey");
		String eAlgorithm = IDataUtil.getString(pc, "encryptionAlgorithm");
		PGPPrivateKey privateKey = (PGPPrivateKey) IDataUtil.get(pc, "privateKey");
		String password = IDataUtil.getString(pc, "privateKeyPassword");
		String sAlgorithm = IDataUtil.getString(pc, "signingAlgorithm");
		
		// Validate key input
		if (publicKey == null  || !publicKey.isEncryptionKey()) {
		    throw new ServiceException("Public key is empty or not an encryption key");
		} else if (privateKey != null && (password == null || password.equals(""))) {
		    throw new ServiceException("Private key password is empty");
		}
		
		// Get output settings
		String outputType = IDataUtil.getString(pc, "outputType");
		String outputPath = IDataUtil.getString(pc, "outputPath");
		
		// Validate output settings
		if (outputType == null || outputType.equals("")) {
		    outputType = "String";
		} else if (outputType.equals("File")) {
		    try {
		        File file = new File(outputPath);
		        if (file.exists() && !file.canWrite()) {
		            throw new Exception("Destination file is not accessible");
		        } else if (!(file.getParentFile().exists() || file.getParentFile().mkdirs())) {
		            throw new Exception("Destination directory is not accessible");
		        }
		    } catch (Exception e) {
		        throw new ServiceException(e.getMessage());
		    }
		}
		
		// Encrypt data
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int signed = 0;
		try {
		    if (privateKey != null) {
		        // Encrypt & sign
		        char[] pasw = password.toCharArray();
		        PGPEncrypt.encryptAndSign(plainTextStream, out, publicKey,
		                PGPInit.getAlgorithm(eAlgorithm), true, privateKey,
		                pasw, PGPInit.getHashAlgorithm(sAlgorithm));
		        signed = 1;
		    } else {
		        // Encrypt
		        PGPEncrypt.encrypt(plainTextStream, out, publicKey, 
		                PGPInit.getAlgorithm(eAlgorithm), true, null);
		    }
		    if (autoClose) {
		        // Close streams created in service
		        try {
		            plainTextStream.close();
		        } catch (Exception e) {}
		    }
		} catch (PGPException pgpe) {
			Exception e = pgpe.getUnderlyingException();
			throw new ServiceException (e);
		    //throw new ServiceException("Unable to encrypt data: "
		    //        + pgpe.getMessage());
		} catch (NoSuchProviderException nspe) {
		    throw new ServiceException("Unable to encrypt data with keys: "
		            + nspe.getMessage());
		} catch (NoSuchAlgorithmException nsae) {
		    throw new ServiceException("Invalid encryption algorithm: "
		            + nsae.getMessage());
		} catch (SignatureException se) {
		    throw new ServiceException("Invalid signature algorithm: "
		            + se.getMessage());
		} catch (IOException ioe) {
		    throw new ServiceException("Unable to write encrypted data: "
		            + ioe.getMessage());
		}
		
		// Generate output
		if (outputType.equals("File")) {
		    try {
		        File file = new File(outputPath);
		        FileOutputStream fout = new FileOutputStream(file);
		        out.flush();
		        fout.write(out.toByteArray());
		        fout.flush();
		        fout.close();
		        out.close();
		        IDataUtil.put(pc, "cipherTextPath", file.getAbsolutePath());
		    } catch (Exception e) {
		        throw new ServiceException("Unable to write cipher text to file: " 
		                + e.getMessage());
		    }
		} else if (outputType.equals("Bytes")) {
		    try {
		        out.flush();
		        IDataUtil.put(pc, "cipherTextBytes", out.toByteArray());
		        out.close();
		    } catch (Exception e) {
		        throw new ServiceException("Unable to decode cipher data: "
		                + e.getMessage());
		    }
		} else if (outputType.equals("Stream")) {
		    try {
		        out.flush();
		        ByteArrayInputStream stream = new ByteArrayInputStream(out.toByteArray());
		        IDataUtil.put(pc, "cipherTextStream", stream);
		    } catch (Exception e) {
		        throw new ServiceException("Unable to decode cipher data: "
		                + e.getMessage());
		    }
		} else if (outputType.equals("String")) {
		    try {
		        out.flush();
		        IDataUtil.put(pc, "cipherTextString", out.toString("UTF-8"));
		        out.close();
		    } catch (Exception e) {
		        throw new ServiceException("Unable to decode cipher data: "
		                + e.getMessage());
		    }
		}
		
		// Return data
		IDataUtil.put(pc, "signed", String.valueOf(signed));
		pc.destroy();
			
		// --- <<IS-END>> ---

                
	}
}

