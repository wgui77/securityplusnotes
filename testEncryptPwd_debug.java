/*
 * TestEncryptPwd.java
 * The encrypt password funtion for testing purpose
 */

import com.e2ee.base.*;
import com.e2ee.*;
import com.e2ee.client.*;


 //rename file to TestEncryptPwd
public class TestEncryptPwd {
    
    /** Creates a new instance of TestEncryptPwd */
    public TestEncryptPwd() {
    }
    
    public static void main(String [] args){
        System.out.println("hi NEW ok");
        try{
		if(args.length!=2)
		{
		System.out.println("Usage java TestEncryptPwd <config> <classname>");
		System.exit(1);
		}
        String conf = args[0];
		String classname="com.e2ee."+args[1];
		String clearPassword = "ab12XPVA";
		String clearPassword2 = "cd782XBY";
        String userID = "sky";
		System.out.println("Testing class: "+classname);
        System.out.println("Test UserID: "+userID);
        System.out.println("Test Clear Password: "+clearPassword);
        System.out.println("Test Clear Password2: "+clearPassword2);
		
        ISncE2EE e2eecipher = SncE2EE.getInstance(classname);
		e2eecipher.initialize(conf, null);
        String SPIN = e2eecipher.encryptPassword(clearPassword , userID, null);
        String SPIN2 = e2eecipher.encryptPassword(clearPassword2 , userID, null);
        
        System.out.println("Encypted Password (store to database): "+SPIN);
		if(SPIN!=null)
			System.out.println("Store key test OK\n");
		
        System.out.println("=== encryptPassword ===");
        System.out.println("clearPassword    : " + clearPassword);
        System.out.println("userID           : " + userID);
        System.out.println("SPIN             : " + SPIN);
        System.out.println("SPIN length      : " + (SPIN == null ? 0 : SPIN.length()));
        System.out.println("SPIN2            : " + SPIN2);

        
        
        
        
        String [] presession=e2eecipher.preSession(null);
		System.out.println("Pressession code : ");
		System.out.println("Public Key string : "+ presession[2]);


        System.out.println("=== preSession ===");
        System.out.println("sessionID        : " + presession[0]);
        System.out.println("challenge        : " + presession[1]);
        System.out.println("challenge length : " + presession[1].length());
        System.out.println("publicKey        : " + presession[2]);

        if(presession[2]!=null)
			System.out.println("Transaction key test OK\n");
		SncE2EEClient encpter= new SncE2EEClient();
		String EPIN= encpter.encryptPIN1(presession[2], presession[1], clearPassword);
		String EPIN1= encpter.encryptPIN2(presession[2], presession[1], clearPassword2, clearPassword);
		String EPIN2= encpter.encryptPIN2(presession[2], presession[1], clearPassword, clearPassword2);
		System.out.println("Client Password EPIN="+ EPIN);
		System.out.println("Client Password EPIN2="+ EPIN2);

        System.out.println("=== client encryption ===");
        System.out.println("EPIN = [challenge || SHA1(ab12XPVA) || clientRandom] ");
        System.out.println("EPIN             : " + EPIN);
        System.out.println("EPIN length      : " + (EPIN == null ? 0 : EPIN.length()));
        System.out.println("encryptPIN2 / EToken2 = [challenge || SHA1(old password) || SHA1(new password) || clientRandom] ");
        System.out.println("EPIN1 = [challenge || SHA1(cd782XBY) || SHA1(ab12XPVA) || clientRandom] ");
        System.out.println("EPIN1            : " + EPIN1);
        System.out.println("EPIN2 = [challenge || SHA1(ab12XPVA) || SHA1(cd782XBY) || clientRandom] ");
        System.out.println("EPIN2            : " + EPIN2);


		if(EPIN!=null&&EPIN.length()>0)
			System.out.println("Client encryption test OK\n");
			
		boolean verifypassword= e2eecipher.verifyPassword(EPIN, SPIN, userID, presession[1], null);
		System.out.println("verifypassword  result= "+ verifypassword);
        System.out.println("=== verifyPassword ===");
        System.out.println("result           : " + verifypassword);
        System.out.println("EPIN pw is ab12XPVA, spin also uses ab12XPVA");
		if(verifypassword)
			System.out.println("verifypassword  test OK\n");
		try {
			boolean verifypassword2= e2eecipher.verifyPassword(EPIN2, SPIN, userID, presession[1], null);
            System.out.println("=== verifyPassword ===");
            System.out.println("result           : " + verifypassword);
			System.out.println("verifypassword2  result= "+ verifypassword2);
            System.out.println("EPIN2 = [challenge || SHA1(ab12XPVA) || SHA1(cd782XBY) || clientRandom] ");
            System.out.println("[ challenge (20 bytes) | SHA1(ab12XPVA) (20 bytes) | SHA1(cd782XBY) (20 bytes) | clientRandom ]\n" + //
                                "  ^^ checked ^^          ^^ read 20 bytes ^^     ^^ never seen ^^");
            System.out.println("memcpy(hashcomb,      clearpassword.ptr, 20);  // SHA1(pw1)  <- from EPIN2\n" + //
                                "memcpy(hashcomb + 20, hashuserid.ptr,    20);  // SHA1(userID)");
            System.out.println("is_same_bytes(decryptedspin.ptr, hashcomb, 40);\n" + //
                                "// SHA1(pw1) ‖ SHA1(userID)  ==  SHA1(pw1) ‖ SHA1(userID)\n" + //
                                "// TRUE");
		}catch(SncE2EEException e){
			System.out.println("verifypassword2  result= "+ e.getCode()+" "+e.getMessage());
			System.out.println("verifypassword2  test OK\n");
		}
		try {
            System.out.println("=== verifyPassword ===");
            System.out.println("verifipassword1");
			boolean verifypassword1= e2eecipher.verifyPassword(EPIN1, SPIN, userID, presession[1], null);
            System.out.println("result           : " + verifypassword1);
			System.out.println("verifypassword1  result= "+ verifypassword1);
            System.out.println("EPIN1 new pw is cd782XBY, spin uses ab12XPVA. this should fail?");
		}catch(SncE2EEException e){
			System.out.println("verifypassword1  result= "+ e.getCode()+" "+e.getMessage());
			System.out.println("verifypassword1  test OK\n");
            System.out.println("This would fail because:");
            System.out.println("EPIN1 = [challenge || SHA1(cd782XBY) || SHA1(ab12XPVA) || clientRandom] ");
            System.out.println("[ challenge (20 bytes) | SHA1(cd782XBY) (20 bytes) | SHA1(ab12XPVA) (20 bytes) | clientRandom ]\r\n" + //
                                "  ^^ checked ^^          ^^ read 20 bytes ^^    ^^ ignored ^^");
            System.out.println("HSM reads `SHA1(pw2)` and builds: \n" + "hashcomb = SHA1(pw2) ‖ SHA1(userID)\n" + //
                                "");
            System.out.println("SPIN = SHA1(pw1) ‖ SHA1(userID)");
            System.out.println("SHA1(pw2) ‖ SHA1(userID)   ← from EPIN1\n" + //
                                "        !=\n" + //
                                "SHA1(pw1) ‖ SHA1(userID)   ← from SPIN");
		}
                
		
		
		String resetPassword = e2eecipher.resetPassword(EPIN, userID, presession[1], null);
		System.out.println("resetPassword result= "+ resetPassword);
		System.out.println("=== resetPassword ===");
        System.out.println("resetPassword new SPIN         : " + resetPassword);
        System.out.println("resetPassword same as SPIN?    : " + resetPassword.equals(SPIN));  // should be true since EPIN carries pw1
        System.out.println("EPIN = [challenge || SHA1(ab12XPVA) || clientRandom] ");
        System.out.println("so obviously, it will be the same as SPIN = ( SHA1(ab12XPVA) ‖ SHA1(userID) )");
		if(resetPassword!=null&&resetPassword.length()>0)
			System.out.println("resetPassword test OK\n");
			
        String EPINforReset = encpter.encryptPIN1(presession[2], presession[1], clearPassword2);
        System.out.println("EPINforReset = [challenge || SHA1(cd782XBY) || clientRandom] ");
        String properReset = e2eecipher.resetPassword(EPINforReset, userID, presession[1], null);
        System.out.println("EPINforReset same as SPIN?  : " + properReset.equals(SPIN));   // false — SPIN =  ( SHA1(ab12XPVA) ‖ SHA1(userID) 
        System.out.println("EPINforReset same as SPIN2? : " + properReset.equals(SPIN2));  // true — SPIN2 =  ( SHA1(cd782XBY) ‖ SHA1(userID) 
			
			
		String changepassword1=e2eecipher.changePassword(EPIN2, SPIN, new String[0], userID, presession[1], null); 	
		System.out.println("we are changing to EPIN2's password. which is cd782XBY");
        System.out.println("changepassword result= "+ changepassword1);
		if(changepassword1!=null&&changepassword1.length()>0)
			System.out.println("changePassword test OK\n");
		System.out.println("=== changePassword ===");
        System.out.println("new SPIN         : " + changepassword1); 
        System.out.println("SPIN = ( SHA1(cd782XBY) ‖ SHA1(userID) )");
        System.out.println("same as SPIN?    : " + changepassword1.equals(SPIN)); // should be false
        System.out.println(" SPIN = ( SHA1(ab12XPVA) ‖ SHA1(userID) )");   
        System.out.println("same as SPIN2?   : " + changepassword1.equals(SPIN2));  // should be true
		System.out.println("SPIN2 = ( SHA1(cd782XBY) ‖ SHA1(userID) )");  
		try {
			String [] his= new String[1];
			his[0]= SPIN2;
			String changepassword2=e2eecipher.changePassword(EPIN2, SPIN,his , userID, presession[1], null); 	
			System.out.println("changepassword2  result= "+ changepassword2);
		}catch(SncE2EEException e){
			System.out.println("changepassword2  result= "+ e.getCode()+" "+e.getMessage());
			System.out.println("changepassword2  test OK\n");
            System.out.println("This would prompt password is in history");
            System.out.println("EPIN2 / EToken2 =[challenge || SHA1(ab12XPVA) || SHA1(cd782XBY) || clientRandom] \n" + //
                                "                                  ^^old^^          ^^new^^");
            System.out.println("HSM reads 40 bytes after challenge:");
            System.out.println("oldpin = SHA1(pw1)   // bytes 0-19\n" + //
                                "newpin = SHA1(pw2)   // bytes 20-39");
            System.out.println("**Stage 1 — verify old password:**\n" + //
                                "hashcomb1 = SHA1(pw1) ‖ SHA1(userID)\n" + //
                                "decrypted SPIN = SHA1(pw1) ‖ SHA1(userID)\n" + //
                                "match! → old password verified");
            System.out.println("**Stage 2 — check history `[SPIN2]`:**\n" + //
 
                                "hashcomb2 = SHA1(pw2) ‖ SHA1(userID)   ← the new password\n" + //
                                "\n" + //
                                "AES_decrypt(SPIN2) = SHA1(pw2) ‖ SHA1(userID)   ← history entry\n" + //
                                "\n" + //
                                "SHA1(pw2) ‖ SHA1(userID)  ==  SHA1(pw2) ‖ SHA1(userID)\n" + //
                                "match! → new password found in history");
		}
		try {
			String [] his= new String[1];
			his[0]= SPIN2;
			String changepassword3=e2eecipher.changePassword(EPIN1, SPIN,his , userID, presession[1], null); 	
			System.out.println("changepassword3  result= "+ changepassword3);
		}catch(SncE2EEException e){
			System.out.println("changepassword3  result= "+ e.getCode()+" "+e.getMessage());
			System.out.println("changepassword3  test OK\n");
		}
		
		}catch (Exception se){
            se.printStackTrace();
        }
        
    }
    
}
