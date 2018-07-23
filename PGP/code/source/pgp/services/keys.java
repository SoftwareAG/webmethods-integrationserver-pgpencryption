package pgp.services;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import java.util.Iterator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import com.softwareag.pgp.PGPInit;
import com.softwareag.pgp.PGPKeyReader;
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataFactory;
import com.wm.data.IDataUtil;
// --- <<IS-END-IMPORTS>> ---

public final class keys

{
	// ---( internal utility methods )---

	final static keys _instance = new keys();

	static keys _newInstance() { return new keys(); }

	static keys _cast(Object o) { return (keys)o; }

	// ---( server methods )---




	public static final void listEncryptionAlgorithms (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(listEncryptionAlgorithms)>> ---
		// @specification pgp.specifications:listAlgorithmsSpec
		// @subtype unknown
		// @sigtype java 3.5
		// Return values
		IDataCursor pc = pipeline.getCursor();
		IDataUtil.put(pc, "algorithms", 
		        PGPInit.listEncryptionAlgorithms().toArray(new String[0]));
		pc.destroy();
		
			
		// --- <<IS-END>> ---

                
	}



	public static final void listKeyExchangeAlgorithms (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(listKeyExchangeAlgorithms)>> ---
		// @specification pgp.specifications:listAlgorithmsSpec
		// @subtype unknown
		// @sigtype java 3.5
		
		// Return values
		IDataCursor pc = pipeline.getCursor();
		IDataUtil.put(pc, "algorithms", 
		        PGPInit.listKeyExchangeAlgorithms().toArray(new String[0]));
		pc.destroy();
		
		// --- <<IS-END>> ---

                
	}



	public static final void listSignatureAlgorithms (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(listSignatureAlgorithms)>> ---
		// @specification pgp.specifications:listAlgorithmsSpec
		// @subtype unknown
		// @sigtype java 3.5
		
		// Return values
		IDataCursor pc = pipeline.getCursor();
		IDataUtil.put(pc, "algorithms", 
		        PGPInit.listSignatureAlgorithms().toArray(new String[0]));
		pc.destroy();
		
		// --- <<IS-END>> ---

                
	}



	public static final void readPrivateKeys (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(readPrivateKeys)>> ---
		// @specification pgp.specifications:readPrivateKeysSpec
		// @subtype unknown
		// @sigtype java 3.5
		
		// Get input
		IDataCursor pc = pipeline.getCursor();
		String path = IDataUtil.getString(pc, "path");
		String pasw = IDataUtil.getString(pc, "password");
		
		// Read private keys from file
		IData data = IDataFactory.create();
		PGPSecretKeyRingCollection ringSecret = null;
		try {
		    IDataCursor dc = data.getCursor();
		    //path = Test.test();
		    //path = PGPKeyReader.test();
		    ringSecret = PGPKeyReader.readSecretKeyRing(path);
		    IDataUtil.put(dc, "privateKeyRing", ringSecret);
		    if (pasw != null) {
		        main: for (Iterator<?> i = ringSecret.getKeyRings(); i.hasNext();) {
		            PGPSecretKeyRing ring = (PGPSecretKeyRing) i.next();
		            for (Iterator<?> j = ring.getSecretKeys(); j.hasNext();) {
		                PGPSecretKey next = (PGPSecretKey) j.next();
		                try {
		                    PGPPrivateKey key = next.extractPrivateKey(pasw.toCharArray(), PGPInit.PROVIDER);
		                    if (key != null) {
		                        IDataUtil.put(dc, "privateKey", key);
		                        IDataUtil.put(dc, "keyId", String.valueOf(key.getKeyID()));
		                        IDataUtil.put(dc, "algorithm", key.getKey().getAlgorithm());
		                        IDataUtil.put(dc, "format", key.getKey().getFormat());
		                        IDataUtil.put(dc, "isSigningKey", String.valueOf(next.isSigningKey()));
		                        IDataUtil.put(dc, "isMasterKey", String.valueOf(next.isMasterKey()));
		                        break main;
		                    }
		                } catch (Exception e) {}
		            }
		        }
		    }
		    dc.destroy();
		} catch (Exception e) {
		    throw new RuntimeException("Unable to read private key file: "
		            + e.getMessage());
		}
		
		// Return data
		IDataUtil.put(pc, "privateKeyData", data);
		pc.destroy();
		// --- <<IS-END>> ---

                
	}



	public static final void readPublicKeys (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(readPublicKeys)>> ---
		// @specification pgp.specifications:readPublicKeysSpec
		// @subtype unknown
		// @sigtype java 3.5
		// Get input
		IDataCursor pc = pipeline.getCursor();
		String path = IDataUtil.getString(pc, "path");
		String alg = IDataUtil.getString(pc, "keyExchangeAlgorithm");
		
		
		// Read public keys from file
		IData data = IDataFactory.create();
		PGPPublicKeyRingCollection ringPub = null;
		PGPPublicKey keyPub = null;
		try {
		    IDataCursor dc = data.getCursor();
		    ringPub = PGPKeyReader.readPublicKeyRing(path);
		    IDataUtil.put(dc, "publicKeyRing", ringPub);
		    if (alg != null) {
		        keyPub = PGPKeyReader.readPublicKey(ringPub,
		                PGPInit.getKeyExchangeAlgorithm(alg));
		        IDataUtil.put(dc, "publicKey", keyPub);
		        IDataUtil.put(dc, "keyId", String.valueOf(keyPub.getKeyID()));
		        IDataUtil.put(dc, "algorithm", String.valueOf(keyPub.getAlgorithm()));
		        IDataUtil.put(dc, "bitStrength", String.valueOf(keyPub.getBitStrength()));
		        IDataUtil.put(dc, "isEncryptionKey", String.valueOf(keyPub.isEncryptionKey()));
		        IDataUtil.put(dc, "isMasterKey", String.valueOf(keyPub.isMasterKey()));
		        IDataUtil.put(dc, "isRevoked", String.valueOf(keyPub.isRevoked()));
		    }
		    dc.destroy();
		} catch (Exception e) {
		    throw new ServiceException("Unable to read key file: "
		            + e.getMessage());
		}
		
		// Return data
		IDataUtil.put(pc, "publicKeyData", data);
		pc.destroy();
			
		// --- <<IS-END>> ---

                
	}
}

