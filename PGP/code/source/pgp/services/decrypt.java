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
package pgp.services;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
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
import java.security.NoSuchProviderException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import com.softwareag.pgp.PGPDecrypt;
import com.wm.app.b2b.server.ServiceException;
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataUtil;
// --- <<IS-END-IMPORTS>> ---

public final class decrypt

{
	// ---( internal utility methods )---

	final static decrypt _instance = new decrypt();

	static decrypt _newInstance() { return new decrypt(); }

	static decrypt _cast(Object o) { return (decrypt)o; }

	// ---( server methods )---




	public static final void decryptAndVerify (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(decryptAndVerify)>> ---
		// @specification pgp.specifications:decryptAndVerifySpec
		// @subtype unknown
		// @sigtype java 3.5
		
		// Get plain text input
		IDataCursor pc = pipeline.getCursor();
		String cipherTextPath = IDataUtil.getString(pc, "cipherTextPath");
		byte[] cipherTextBytes = (byte[]) IDataUtil.get(pc, "cipherTextBytes");
		String cipherText = IDataUtil.getString(pc, "cipherTextString");
		InputStream cipherTextStream = (InputStream) IDataUtil.get(pc, "cipherTextStream");
		String plainTextEncoding = IDataUtil.getString(pc, "plainTextEncoding");
		
		// Validate plain text input
		boolean autoClose = false;
		try {
		    if (cipherTextPath != null && !cipherTextPath.equals("")) {
		        cipherTextStream = new FileInputStream(new File(cipherTextPath));
		        autoClose = true;
		    } else if (cipherTextBytes != null && cipherTextBytes.length > 0) {
		        cipherTextStream = new ByteArrayInputStream(cipherTextBytes);
		        autoClose = true;
		    } else if (cipherText != null && !cipherText.equals("")) {
		        cipherTextStream = new ByteArrayInputStream(
		                cipherText.getBytes("UTF-8"));
		        autoClose = true;
		    } else {
		        // Throws an exception if unavailable
		        cipherTextStream.available();
		    }
		} catch (FileNotFoundException fnfe) {
		    throw new ServiceException("Cipher text file was not found: "
		            + fnfe.getMessage());
		} catch (UnsupportedEncodingException uee) {
		    throw new ServiceException("Cipher text encoding is invalid: "
		            + uee.getMessage());
		} catch (IOException ioe) {
		    throw new ServiceException("Cipher text stream is empty: "
		            + ioe.getMessage());
		} catch (NullPointerException npe) {
		    throw new ServiceException("No cipher data available: "
		            + npe.getMessage());
		}
		if (plainTextEncoding == null || plainTextEncoding.equals("")) {
		    plainTextEncoding = "UTF-8";
		} else if (!Charset.isSupported(plainTextEncoding)) {
		    throw new ServiceException("Unsupported character encoding");
		}
		
		// Get key input
		PGPPublicKeyRingCollection ringPub = (PGPPublicKeyRingCollection) IDataUtil
		        .get(pc, "publicKeyRingCollection");
		PGPSecretKeyRingCollection ringSecret = (PGPSecretKeyRingCollection) IDataUtil
		        .get(pc, "privateKeyRingCollection");
		String password = IDataUtil.getString(pc, "privateKeyPassword");
		
		// Validate key input
		if (ringSecret == null || ringSecret.size() == 0) {
		    throw new ServiceException("Private key ring is empty");
		} else if (password == null || password.equals("")) {
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
		
		// Decrypt data
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int verified = 0;
		try {
		    char[] pasw = password.toCharArray();
		    if (ringPub != null) {
		        // Decrypt & verify
		        verified = PGPDecrypt.decryptAndVerify(cipherTextStream, out,
		                ringSecret, pasw, ringPub);
		    } else {
		        // Decrypt
		        PGPDecrypt.decrypt(cipherTextStream, out, ringSecret, pasw);
		    }
		    if (autoClose) {
		        // Close streams created in service
		        try {
		            cipherTextStream.close();
		        } catch (Exception e) {}
		    }
		} catch (PGPException pgpe) {
		    throw new ServiceException("Unable to decrypt data (possibly invalid password): "
		            + pgpe.getMessage());
		} catch (NoSuchProviderException nspe) {
		    throw new ServiceException("Unable to decrypt data with given keys: "
		            + nspe.getMessage());
		} catch (IOException ioe) {
		    throw new ServiceException("Unable to write decrypted data: "
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
		        IDataUtil.put(pc, "plainTextPath", file.getAbsolutePath());
		    } catch (Exception e) {
		        throw new ServiceException("Unable to write plain text to file: " 
		                + e.getMessage());
		    }
		} else if (outputType.equals("Bytes")) {
		    try {
		        out.flush();
		        IDataUtil.put(pc, "plainTextBytes", out.toByteArray());
		        out.close();
		    } catch (Exception e) {
		        throw new ServiceException("Unable to encode plain data: "
		                + e.getMessage());
		    }
		} else if (outputType.equals("Stream")) {
		    try {
		        out.flush();
		        ByteArrayInputStream stream = new ByteArrayInputStream(out.toByteArray());
		        IDataUtil.put(pc, "plainTextStream",stream);
		    } catch (Exception e) {
		        throw new ServiceException("Unable to encode plain data: "
		                + e.getMessage());
		    }
		} else if (outputType.equals("String")) {
		    try {
		        out.flush();
		        IDataUtil.put(pc, "plainTextString", out.toString(plainTextEncoding));
		        out.close();
		    } catch (Exception e) {
		        throw new ServiceException("Unable to encode plain data: "
		                + e.getMessage());
		    }
		}
		
		// Return data
		IDataUtil.put(pc, "verified", String.valueOf(verified));
		pc.destroy();
		// --- <<IS-END>> ---

                
	}
}

