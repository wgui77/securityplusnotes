

package com..e2ee.client;

import java.util.*;

import com..e2ee.base.*;

public class SncE2EEClient implements ISncE2EEClient{
	private static final int MAX_PASSWORD_LEN=SncE2EECode.HASH_SIZE;
	
    public SncE2EEClient(){
    
    }

	// 1) public Key Value is Hex
	// 2) random number value is Hex
	// 3) pin the the raw data
	
    public String encryptPIN1(String publicKeyValue, String randomNumber, String pin) throws Exception{
    	
    	String eToken1 = null;
    	byte[] pinPackage = null;
    	
        byte[] hashPin = hashProcess(SncE2EECode.HASH_METHOD, pin.getBytes());
        byte[] clientRandom = randomProcess(SncE2EECode.CLIENT_RANDOM_SIZE);
        byte[] serverRandom = HexBin.decode(randomNumber.getBytes());
        EToken1 et1 = new EToken1(serverRandom, hashPin, clientRandom);
        
    	pinPackage = et1.pack();  
	
		//System.out.println("Clear Token1: "+new String(HexBin.encode(pinPackage)));
              
 		byte encryptedToken1 [] = rsaEncryptProcess(pinPackage, publicKeyValue); 
    	eToken1 = new String(HexBin.encode(encryptedToken1));
    
        return eToken1;
        
    }

	// all the parameters are the Hex value already
	
    public String encryptPIN2(String publicKeyValue, String randomNumber, String oldPin,
    String newpin) throws Exception{
        
       	String eToken2 = null;
    	byte[] pinPackage = null;
    	
        byte[] hashOldPin = hashProcess(SncE2EECode.HASH_METHOD, oldPin.getBytes());
        byte[] hashNewPin = hashProcess(SncE2EECode.HASH_METHOD, newpin.getBytes());
        byte[] clientRandom = randomProcess(SncE2EECode.CLIENT_RANDOM_SIZE);
        byte[] serverRandom = HexBin.decode(randomNumber.getBytes());

        
        EToken2 et2 = new EToken2(serverRandom, hashOldPin, hashNewPin,clientRandom);
        
    	pinPackage = et2.pack();  
	
		//System.out.println("Clear Token2: "+new String(HexBin.encode(pinPackage)));
              
 		byte encryptedToken2 [] = rsaEncryptProcess(pinPackage, publicKeyValue); 
    	eToken2 = new String(HexBin.encode(encryptedToken2));
    
        return eToken2;
    }
    
    public String encryptPIN3(String publicKeyValue, String randomNumber, String oldPin,
    	    String newpin) throws Exception{
    	        
    	       	String eToken2 = null;
    	    	byte[] pinPackage = null;
    	    	
    	        byte[] hashOldPin = hashProcess(SncE2EECode.HASH_METHOD, oldPin.getBytes());
    	        byte[] newPin = PKCS5Padding(newpin.getBytes(),MAX_PASSWORD_LEN);
    	        byte[] clientRandom = randomProcess(SncE2EECode.CLIENT_RANDOM_SIZE);
    	        byte[] serverRandom = HexBin.decode(randomNumber.getBytes());

    	        
    	        EToken2 et2 = new EToken2(serverRandom, hashOldPin, newPin,clientRandom);
    	        
    	    	pinPackage = et2.pack();  
    		
    			//System.out.println("Clear Token2: "+new String(HexBin.encode(pinPackage)));
    	              
    	 		byte encryptedToken2 [] = rsaEncryptProcess(pinPackage, publicKeyValue); 
    	    	eToken2 = new String(HexBin.encode(encryptedToken2));
    	    
    	        return eToken2;
    	   }
   
   //Crypto Help Utility Class
   
   /**
	 * @param bytes
	 * @param maxPasswordLen
	 * @return
	 */
	private byte[] PKCS5Padding(byte[] bytes, int maxPasswordLen) throws Exception{
		int inputlen;
		if(bytes==null)
			inputlen=0;
		else
			inputlen=bytes.length;
		if(inputlen>maxPasswordLen)
			throw new Exception("Input length is greater than maximum length allowed.");
		byte [] ret= new byte[maxPasswordLen];
		int padlen= maxPasswordLen - inputlen;
		System.arraycopy(bytes, 0, ret, 0, inputlen);
		for(int i=inputlen; i<maxPasswordLen; i++)
			ret[i]=(byte)padlen;
		return ret;
	}

private  byte[] hashProcess(String hashMethod, byte[] inputData) throws java.security.NoSuchAlgorithmException {
	if("SHA-1".equals(hashMethod)){
        SHA1Digest sha1 = new SHA1Digest();
        sha1.update(inputData, 0, inputData.length);
        byte [] hashBuf = new byte[sha1.getDigestSize()];
        sha1.doFinal(hashBuf, 0);
        return hashBuf;
    }else{
    	return null;
    }
	}

    
   private byte[] randomProcess(int size) throws Exception {
    	
		Random randomGenerator = new Random();		// pseudo-random using current time
    	byte[] plainText = new byte[size];
    	randomGenerator.nextBytes( plainText );
    	return plainText;
  }

  
	//public key format:  [modulus]+":"+[modulus]
  private byte[] rsaEncryptProcess(byte[] inputDataByteArray, String publicKey)throws Exception   
  {
  	RSAEngine rsa = new RSAEngine();
  	rsa.init(true, new RSAKeyParameters(publicKey));
    
    PKCS1Encoding so = new PKCS1Encoding(rsa);
    so.init(true, new RSAKeyParameters(publicKey));
  
  	return so.processBlock(inputDataByteArray, 0, inputDataByteArray.length);
  	
  }


      
}
