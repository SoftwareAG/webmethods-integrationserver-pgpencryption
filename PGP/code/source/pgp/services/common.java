package pgp.services;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import com.wm.app.b2b.server.Server;
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataUtil;
// --- <<IS-END-IMPORTS>> ---

public final class common

{
	// ---( internal utility methods )---

	final static common _instance = new common();

	static common _newInstance() { return new common(); }

	static common _cast(Object o) { return (common)o; }

	// ---( server methods )---




	public static final void getFileContent (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getFileContent)>> ---
		// @specification pgp.specifications:getFileContentSpec
		// @subtype unknown
		// @sigtype java 3.5
		
		// Get input
		IDataCursor pc = pipeline.getCursor();
		String path = IDataUtil.getString(pc, "path");
		String encoding = IDataUtil.getString(pc, "encoding");
		
		// Validate input
		if (path == null || path.equals("")) {
		    throw new ServiceException("Path cannot be empty");
		}
		if (encoding == null || encoding.equals("")) {
		    encoding = "UTF-8";
		} else if (!Charset.isSupported(encoding)) {
		    throw new ServiceException("Unsupported character encoding");
		}
		
		// Read file 
		FileInputStream in = null;
		ByteArrayOutputStream out = null;
		try {
		    in = new FileInputStream(new File(path));
		    out = new ByteArrayOutputStream();
		    byte[] buffer = new byte[8192];
		    int read = 0;
		    while ((read = in.read(buffer)) > 0) {
		        out.write(buffer, 0, read);
		    }
		    out.flush();
		    IDataUtil.put(pc, "content", out.toString(encoding));
		} catch (Exception e) {
		    throw new ServiceException("Unable to read file content");
		} finally {
		    try {
		        in.close();
		        out.close();
		    } catch (Exception e) {}
		}
		pc.destroy();
		
		// --- <<IS-END>> ---

                
	}



	public static final void getPackagePath (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getPackagePath)>> ---
		// @specification pgp.specifications:getPackagePathSpec
		// @subtype unknown
		// @sigtype java 3.5
		
		// Handle input params
		IDataCursor pc = pipeline.getCursor();
		String packageName = IDataUtil.getString(pc, "package");
		String subdir      = IDataUtil.getString(pc, "subDir");
		String filename    = IDataUtil.getString(pc, "fileName");
		
		if (packageName == null) {
		    packageName = Service.getServiceEntry().getPackage().getName();
		}
		
		String packageDir = Server.getResources().getPackageDir(packageName)
		    .getAbsolutePath().concat(File.separator);
		
		if (new File(packageDir).exists()) {
		    if (subdir != null) {
		        packageDir = packageDir.concat(subdir).concat(File.separator);
		    }
		    if (filename != null) {
		        packageDir = packageDir.concat(filename);
		    }
		    IDataUtil.put(pc, "path", packageDir);
		}
		pc.destroy();
		
		// --- <<IS-END>> ---

                
	}



	public static final void getSupportedEncodings (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getSupportedEncodings)>> ---
		// @specification pgp.specifications:getSupportedEncodingsSpec
		// @subtype unknown
		// @sigtype java 3.5
		
		// Get input
		IDataCursor pc = pipeline.getCursor();
		String encoding = IDataUtil.getString(pc, "encoding");
		
		// Validate input
		if (encoding != null && !encoding.equals("")) {
		    IDataUtil.put(pc, "isSupported", String.valueOf(Charset.isSupported(encoding)));
		}
		
		// Get supported encodings
		IDataUtil.put(pc, "encodings", 
		        Charset.availableCharsets().keySet().toArray(new String[0]));
		IDataUtil.put(pc, "default", Charset.defaultCharset().name());
		pc.destroy();
		
		// --- <<IS-END>> ---

                
	}



	public static final void selectFromConfig (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(selectFromConfig)>> ---
		// @sigtype java 3.5
		// [i] recref:0:required config pgp.documents.config:PGPconfig
		// [i] field:0:required userId
		// [o] recref:0:required key pgp.documents.config:KeyConfig
		Map<String, IData> configCache = new HashMap<String, IData>();
		
		// pipeline
		IDataCursor pipelineCursor = pipeline.getCursor();
		
			// config
			String userId  = IDataUtil.getString(pipelineCursor, "userId");
			IData	config = IDataUtil.getIData( pipelineCursor, "config" );
			
			
			if ( config != null)
			{
				IDataCursor configCursor = config.getCursor();
					IData	keys = IDataUtil.getIData( configCursor, "keys" );
					if ( keys != null)
					{
						IDataCursor keysCursor = keys.getCursor();
							IData[]	key = IDataUtil.getIDataArray( keysCursor, "key" );
							if ( key != null)
							{
								for ( int i = 0; i < key.length; i++ )
								{
									IDataCursor keyCursor = key[i].getCursor();
										String	__userId = IDataUtil.getString( keyCursor, "@userId" );
										
										configCache.put(__userId, key[i]);
		
									keyCursor.destroy();
								}
							}
						keysCursor.destroy();
					}
				configCursor.destroy();
			}
		pipelineCursor.destroy();
		
		
		IData key = configCache.get(userId);
		
		IDataCursor pipelineCursor_1 = pipeline.getCursor();
			 IDataUtil.put( pipelineCursor_1, "key", key );
		pipelineCursor_1.destroy();
		// pipeline
		
			
		// --- <<IS-END>> ---

                
	}

	// --- <<IS-START-SHARED>> ---



	
	// --- <<IS-END-SHARED>> ---
}

