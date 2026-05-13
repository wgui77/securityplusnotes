


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "seelib.h"
#include "common.h"
#include "e2ee_proc.h"
#include "signers.h"
#include <assert.h>
#include "e2ee_utils.h"

/* For extra debug */
#ifdef _DEBUG_
#define DEBUG(a) printf a 
#else
#define DEBUG(a)
#endif

//three status of activation status
#define ACTIVATED 1
#define INACTIVATE 2
#define UNCHECKED 0
#define EVALUATION 3
//predefined seperator which is not in the hex value
#define SEP 16
//user pin length 
#define USERPINLEN 20 
#define CHALLENGELEN 20 
#define HASHLEN 20 
//ESN Length
#define ESNLEN 14
// Global key IDs  
// static M_KeyID private_key = 0, store_key=0;
// static M_KeyID new_store_key=0;
//static see_key_type cur_storekey_type=UNDEFINED;
//static see_key_type new_storekey_type=UNDEFINED;

static unsigned char activation_status=UNCHECKED;
typedef enum  {UNDEFINED, DES3, AES, RSA} see_key_type;
//predefined evaluation key
// static const unsigned char * eval_license= "-E2EE-EVAL-KEY";
static const unsigned char * eval_license = (const unsigned char *)"-E2EE-EVAL-KEY"; // NEW
static const char pubmod[128]= {237,1,23,245,197,86,36,72,183,206,19,20,19,182,168,157,91,134,9,34,225,47,66,117,112,100,46,235,74,245,95,229,212,155,58,71,79,21,71,250,23,107,241,180,154,14,101,198,136,62,211,86,215,64,213,31,209,218,53,220,220,65,231,174,53,43,158,2,240,150,183,101,6,254,220,76,40,193,50,124,81,199,139,122,222,89,233,39,29,65,220,62,39,47,90,4,70,128,240,5,108,253,104,212,133,19,147,84,96,24,25,116,50,244,242,10,159,71,166,50,113,8,181,252,10,89,20,166};//"a614590afcb5087132a6479f0af2f4327419186054931385d468fd6c05f08046045a2f273edc411d27e959de7a8bc7517c32c1284cdcfe0665b796f0029e2b35aee741dcdc35dad11fd540d756d33e88c6650e9ab4f16b17fa47154f473a9bd4e55ff54aeb2e647075422fe12209865b9da8b6131413ceb7482456c5f51701ed";
static const char pubexp [4] = {1,0,1,0};
// static const char * see_version="0.1.0.3";
static const unsigned char * see_version = (const unsigned char *)"1.0.0"; // NEW
static const M_Word pubmodlen=128;
static const M_Word pubexplen=4;
//loaded public key 
//M_KeyID licpubkeyid=0;
typedef struct see_key{
M_KeyID keyid; 
see_key_type keytype;
} see_key;

typedef struct see_loaded_key {
see_key key; 
unsigned char * keyhash;
} see_loaded_key;

static see_loaded_key * key_list=NULL;
static M_Word key_list_size =0;

//tell if a key with the hash has been loaded
static unsigned char is_loaded (const unsigned char * keyhash, M_Word len){
	DEBUG(("is_loaded, keylist size: %d\n", key_list_size));
	M_Word i;
	
	if(keyhash==NULL){
		DEBUG(("check load fails, the hash is NULL."));
		return FALSE;
	}
	printHex("keyhash", keyhash, len);
	if(len!=HASHLEN){
		DEBUG(("Hash len not right.\n"));
		return FALSE;
	}
	for(i=0; i<key_list_size; i++){
		see_loaded_key key_temp=key_list[i];
		printHex("key_list[i]", key_list[i].keyhash, HASHLEN);
		if(is_same_bytes(keyhash, key_temp.keyhash, HASHLEN))
			return TRUE;
	}
	return FALSE;
}


//retrieve the key
static M_Word getLoadedKey (const unsigned char * keyhash, M_Word len,  see_key * loadedkey ){
	M_Word i;
	
	if(keyhash==NULL||len!=HASHLEN){
	//in case of invalid input
		return FALSE;
	}
	printHex("keyhashx", keyhash, len);
	for(i=0; i<key_list_size; i++){
		see_loaded_key key_temp=key_list[i];
		printHex("key_listx[i]", key_list[i].keyhash, HASHLEN);
		if(is_same_bytes(keyhash, key_temp.keyhash, HASHLEN))
		{ 
			DEBUG(("found loaded key\n"));
			loadedkey->keyid=key_temp.key.keyid;
			loadedkey->keytype=key_temp.key.keytype;			
			return TRUE;
		}
	}
	return FALSE;
}

//Add a newly loaded key to the key store
static M_Word addLoadedKey (const unsigned char * keyhash, M_Word len, M_KeyID newkeyid, see_key_type newkeytype){
	M_Word i;
	M_ByteBlock hash;
	
	if(keyhash==NULL){
		return FALSE;
	}
	if(is_loaded(keyhash, len)!=TRUE){
		see_loaded_key * temp_key_list=malloc((key_list_size+1)*sizeof(see_loaded_key));
		DEBUG(("!extending the list\n"));
		if(temp_key_list!=NULL){
			for(i=0; i<key_list_size;i++){
				temp_key_list[i]=key_list[i];
			}
			DEBUG(("copied list\n"));
			dup_data(keyhash, HASHLEN, &hash); 
			
			temp_key_list[key_list_size].keyhash=hash.ptr;
			temp_key_list[key_list_size].key.keyid=newkeyid;
			temp_key_list[key_list_size].key.keytype=newkeytype;
			free(key_list);
			
			key_list =temp_key_list;
			key_list_size=key_list_size+1;
			DEBUG(("new list size:%d\n", key_list_size));
			return TRUE;
		}
		else{
			DEBUG(("Failed to allocate memeory to new key"));
			return FALSE;
		}
	}
	else{
		DEBUG(("The key has been loaded"));
		return FALSE;
		
	}
	
}

//static void gethash(const unsigned char* text, M_Word len, M_ByteBlock *hash);
//get the hash value of given text
static void gethash(const unsigned char* text, M_Word len, M_ByteBlock * hashres){
	M_Command cmd;
	M_Reply reply;  
	M_Word rc;
	M_ByteBlock data;
	hashres->ptr=NULL;
	memset(&cmd, 0, sizeof(cmd)); 
	memset(&reply, 0, sizeof(reply));
	cmd.cmd = Cmd_Hash;
	cmd.args.hash.mech=Mech_SHA1Hash;
	cmd.args.hash.plain.type=PlainTextType_Bytes;
	dup_data(text, len, &data);
	cmd.args.hash.plain.data.bytes.data=data;
	
	if ((rc = signers_transact(&cmd, &reply)) == Status_OK) {
		hashres->ptr= malloc(20);
		if(hashres->ptr==NULL){
			DEBUG(("Fail to allocate memory for hash value.\n"));
		}else{	
			hashres->len=20;
			memcpy( hashres->ptr,reply.reply.hash.sig.data.sha1hash.h.bytes, 20);
		}
	}
	
	SEElib_FreeCommand(&cmd);
	SEElib_FreeReply(&reply);
}

//get current activation status
static void get_status (M_ByteBlock *status){
	if((status->ptr=malloc(1))!=NULL){
		status->ptr[0]=activation_status;
		status->len=1;
	}
}

//get current activation status
static void check_key_loaded (const unsigned char *ptr, M_Word len, M_ByteBlock * result){
	DEBUG(("checking key loading"));
	if((result->ptr=malloc(1))!=NULL){
		result->ptr[0]=is_loaded(ptr, len);
		result->len=1;
	}
}

//get the current version of see running
static void get_version (M_ByteBlock *version){
	//duplicate the see version content to version
	dup_data(see_version, 7, version);
}


//retrieve the current esn of module
static M_ByteBlock getESN ( void){
	M_ByteBlock ret;

	M_Command cmd;
	M_Reply reply;
	M_Status result;
	
	if((ret.ptr=malloc(ESNLEN))!=NULL){
		memset(&cmd, 0, sizeof(cmd));
		memset(&reply, 0, sizeof(reply));
		cmd.cmd = Cmd_NewEnquiry;	
		cmd.args.newenquiry.module= 0;
		cmd.args.newenquiry.version= EnqVer_Six;
		result = signers_transact(&cmd, &reply);
		//Copy the content over and close the command
		if(result==Status_OK&&reply.reply.newenquiry.data.one.one.hardwareserial.ptr!=NULL){
			memcpy(ret.ptr, reply.reply.newenquiry.data.one.one.hardwareserial.ptr, ESNLEN);
			ret.len=ESNLEN;
		}
	}
	//realse the memory of transaction
	SEElib_FreeCommand(&cmd);
	SEElib_FreeReply(&reply);
	
	return ret;
}


//verify the license
static M_Word activate_fips (const unsigned char * activationkey, M_Word len, const unsigned char * esn, M_Word esnlen){ 
	int rc;
	M_Command cmd;
	M_Reply reply;
	unsigned char * encmsg=NULL;
	int enclen=0;
	M_ByteBlock esnhash;
	//counter
	M_Word i;
	//define the three bignumbers
	M_Bignum mod=NULL;
	M_Bignum exp=NULL;
	M_Bignum sig=NULL;
	//allocate 3 operands
	M_Bignum nn[3];
	//only one operation
	M_StackOpVal op[] = { 
	   { StackOp_ModExp }
	};	
	//default returning false
	M_Word retCode=FALSE;
	M_Bignum out;
	unsigned char* bytestoverify=NULL;
	
	if(activationkey==NULL||esn==NULL||len!=128||esnlen!=ESNLEN){
		DEBUG(("invalid Parameter for activation\n"));
		retCode =3;
		goto activate_fips_cleanup;
	}
	
	memset(&cmd, 0, sizeof(cmd));
	memset(&reply, 0, sizeof(reply)); 
	mod=(struct NFast_Bignum *)malloc(sizeof(struct NFast_Bignum));
	if(mod==NULL){
		retCode=4;
		goto activate_fips_cleanup;
	}
	exp=(struct NFast_Bignum *)malloc(sizeof(struct NFast_Bignum));
	if(mod==NULL){
		free(mod);
		retCode=4;
		goto activate_fips_cleanup;
	}
	
	sig=(struct NFast_Bignum *)malloc(sizeof(struct NFast_Bignum));		
	if(mod==NULL){
		free(mod);
		free(exp);
		retCode=4;
		goto activate_fips_cleanup;
	}

	mod->bb.ptr=malloc(128);
	if(mod->bb.ptr==NULL){
		free(mod);
		free(exp);
		free(sig);
		retCode=5;
		goto activate_fips_cleanup;
	}
	
	exp->bb.ptr=malloc(4);
	if(exp->bb.ptr==NULL){
		free(mod);
		free(exp);
		free(sig);
		free(mod->bb.ptr);
		retCode=5;
		goto activate_fips_cleanup;
	}

	sig->bb.ptr=malloc( len);	
	if(sig->bb.ptr==NULL){
		free(mod);
		free(exp);
		free(sig);
		free(mod->bb.ptr);
		free(exp->bb.ptr);
		retCode=5;
		goto activate_fips_cleanup;
	}

	memcpy(mod->bb.ptr, pubmod, pubmodlen);
	mod->bb.len= pubmodlen;	
	memcpy(exp->bb.ptr, pubexp,pubexplen );
	exp->bb.len= pubexplen;
	for(i=0; i<len; i++)
		sig->bb.ptr[i]= activationkey[len-i-1];
	sig->bb.len= len;
	
	nn[0]=sig;
	nn[1]=exp;
	nn[2]=mod;

	cmd.cmd= Cmd_BignumOp;
    cmd.args.bignumop.n_stackin = 3;
    cmd.args.bignumop.stackin = nn;
    cmd.args.bignumop.n_ops = 1;
    cmd.args.bignumop.ops = op;
	
	//rc = signers_transact(&cmd, &reply);
	rc = SEElib_Transact(&cmd, &reply);
	DEBUG(("returning rc== %d\n", reply.status));
	if(rc==Status_OK){
		free(mod);
		free(exp);
		free(sig);
		free(mod->bb.ptr);
		free(exp->bb.ptr);
		free(sig->bb.ptr);
		
		DEBUG(("returning %d results\n", reply.reply.bignumop.n_stackout ));
		out= reply.reply.bignumop.stackout[0];	
		encmsg= ((struct NFast_Bignum *)out)->bb.ptr;
		enclen= ((struct NFast_Bignum *)out)->bb.len;
		if(encmsg==NULL||enclen<20){
			//unvalid decrypted code
			retCode=6;
			goto activate_fips_cleanup;
		}
		
		bytestoverify=malloc(HASHLEN);
		if(bytestoverify==NULL){
		//not able to allocate memory for bytestoverify
			retCode=7;
			goto activate_fips_cleanup;
		}
		//first 20 bytes are the bytes to be verified
		for(i=0; i<HASHLEN;i++)
			bytestoverify[i]= encmsg[HASHLEN-i-1];
		printHex("bytestoverify", bytestoverify, HASHLEN);
		gethash(esn, esnlen, &esnhash);	
		if(esnhash.ptr==NULL){
			free(bytestoverify);
			retCode=8;
			goto activate_fips_cleanup;
		}
		retCode= is_same_bytes(bytestoverify,esnhash.ptr, HASHLEN);
		free(bytestoverify);
		free(esnhash.ptr);
	}
	else{
		free(mod);
		free(exp);
		free(sig);
		free(mod->bb.ptr);
		free(exp->bb.ptr);
		free(sig->bb.ptr);
		retCode= rc+10; //if retCode >10, it will subtract 10, 1-10 reserved for this
	}
	
activate_fips_cleanup:
	SEElib_FreeCommand(&cmd);
	SEElib_FreeReply(&reply);
	return retCode;	
}


//activate current SEEnCipher 
static void activate(const unsigned char * activationkey, M_Word len, M_ByteBlock * result){
/*
return code definition
1: Activated
2: Inactivated
3: Evaluation
4: Retrieve ESN failed
5+: Verification failed with code

*/
	unsigned char * esn=NULL;	
	M_Word verify_rc;
	result->ptr=malloc(1);
	result->len=1;
	result->ptr[0]=activation_status;
	
	if(activation_status!= ACTIVATED){
		esn=getESN().ptr;
		if(esn!=NULL){
			if(activationkey!=NULL&&is_same_bytes(activationkey, eval_license,20)==TRUE){
				DEBUG(("Evaluation key found."));
				activation_status= EVALUATION;		
				result->ptr[0]=	EVALUATION;			
				//goto cleanup;
			}
			else{
				DEBUG(("ver=%s\n", see_version));				
				verify_rc = activate_fips( activationkey, len, esn, ESNLEN);
				if(verify_rc==TRUE){
					DEBUG(("Signature verified. Activation succeeded\n"));
					activation_status= ACTIVATED;
					result->ptr[0]=	ACTIVATED;	
				}else{
					result->ptr[0]= verify_rc+5;
					//activation_status= INACTIVATE;
				}
			}
			free(esn);
		}else
		{
			//esn ==null
			result->ptr[0]=4; 
		}
		
	}
}


//Get the next token in the given string
static void  getnexttoken(const unsigned char * str, M_Word start, M_Word len, M_Word * tokenidx, M_ByteBlock * result){
	//sep marks the seperation point, using the defined mark value
	M_Word sep;

	if(start==len){
		* tokenidx=start;
		result->len=0;
		result->ptr=NULL;
	}
	
	for(sep=start; sep<len; sep++){
		if(str[sep]==SEP)
			break;
	}
	if(sep==len){
		* tokenidx=len;
		hex2byte(str+start, len-start, result);
	}
	else{
		*tokenidx=sep;	
		hex2byte(str+start, sep-start, result);
	}
}

/*perform error report routine*/
static void die(const char *msg, M_Word rc)
{
  // DEBUG(("Module-side fatal error: %s ", msg));
  // if (rc){
    // DEBUG(("(error code %d)", rc));}
  // DEBUG(("\n"));
  // //exit(1);
}


//reset the clear text pin to zeros
static void clearCredentials(unsigned char * ptr, M_Word len){
	M_Word i;
	for(i=0; i<len&&ptr!=NULL; i++){
		ptr[i]='\0'; //reset to nil 
	}
}


//decrypt a RSA cipher text using stored trans key
static M_Word decrypt_rsa (M_KeyID private_key, const unsigned char * epin, M_Word epinlen, unsigned char* challenge, M_Word challengelen, M_Word resultlen, M_ByteBlock* result){
/*
return code definition
1: Big number allocation failed
2: decrypt command not run succesfully
3: decrypted epin length not sufficient
4: challenge not found
5: challenge code is null or length not correct
*/

	M_Command cmd;
	M_Reply reply;
	M_ByteBlock  decryptedepin;
	//M_Word decryptedepinlen=0;
    // struct NFast_Bignum bnepin;
	M_Word rc;
	M_Word i;
	M_Word foundchallenge;
	result->ptr=NULL;
	result->len=0;
	M_Word errorcode=0;
		struct NFast_Bignum *bnepin = (struct NFast_Bignum *)malloc(sizeof(struct NFast_Bignum));
if(bnepin == NULL){
    errorcode = 1;
    return errorcode;
}
	bnepin->bb.ptr=malloc(epinlen);
	if(bnepin->bb.ptr==NULL){
		DEBUG(("Failed to allocate memeory for big number.\n"));
		errorcode=1;
		//goto decrypt_rsa_cleanup;
	}else{
		memset(&cmd, 0, sizeof(cmd));
		memset(&reply, 0, sizeof(reply));
		cmd.cmd=Cmd_Decrypt;
		cmd.args.decrypt.key = private_key;
		cmd.args.decrypt.mech = Mech_RSApPKCS1 ;
		cmd.args.decrypt.cipher.mech = Mech_RSApPKCS1 ;
		for(i=0;i<epinlen;i++)
			bnepin->bb.ptr[i]=epin[epinlen-1-i];
		
		bnepin->bb.len=epinlen;	
		cmd.args.decrypt.cipher.data.rsappkcs1.m=bnepin;
		cmd.args.decrypt.reply_type = PlainTextType_Bytes;
		if ((rc = signers_transact(&cmd, &reply)) == Status_OK) {
			decryptedepin=reply.reply.decrypt.plain.data.bytes.data;
		}
		else{
			errorcode=2;
			DEBUG(("Error occurs during rsa decryption:rc=%d.\n", rc));
			goto decrypt_rsa_cleanup;
		}
		//locate the acctual clear pass.
		if(decryptedepin.ptr==NULL||decryptedepin.len<(challengelen+resultlen)||decryptedepin.len==0) {
			DEBUG(("unsfficient cipher text length for decryption: %d %d \n", decryptedepin.len,challengelen ));
			errorcode=3;
			goto decrypt_rsa_cleanup;
		}
		if(challengelen!=CHALLENGELEN||challenge==NULL){
			DEBUG(("challenge code is null or length not correct, failed to decrypt.\n"));
			errorcode=5;
			goto decrypt_rsa_cleanup;
		}
		foundchallenge=FALSE;
		foundchallenge= is_same_bytes(decryptedepin.ptr, challenge, challengelen);
		
		if(foundchallenge==FALSE){
			DEBUG(("cannot find challenge, failed to decrypt.\n"));
			errorcode=4;
			goto decrypt_rsa_cleanup;
		}	
		result->ptr= malloc(resultlen);
		if(result->ptr!=NULL){
			memcpy(result->ptr, decryptedepin.ptr+challengelen, resultlen);
			result->len=resultlen;
		}else{
			errorcode=1;
			DEBUG(("cannot allocate memory for result.\n"));
			goto decrypt_rsa_cleanup;
		}
	decrypt_rsa_cleanup:
		//free(bnepin.bb.ptr);
		// SEElib_FreeCommand(&cmd);
		// SEElib_FreeReply(&reply);
		DEBUG(("here at decrypt_rsa_cleanrup.\n"));
		if(bnepin != NULL){
        if(bnepin->bb.ptr != NULL){
            free(bnepin->bb.ptr);
            bnepin->bb.ptr = NULL;
        }
		DEBUG(("freeing bnepin\n"));
        free(bnepin);
        bnepin = NULL;
		DEBUG(("after free(bnepin), bnepin supposed to be null: %p\n", bnepin));
        cmd.args.decrypt.cipher.data.rsappkcs1.m = NULL;
    }
		DEBUG(("SEElib_FreeCommand(&cmd)\n"));
		SEElib_FreeCommand(&cmd);
		DEBUG(("SEElib_FreeReply(&reply)\n"));
		SEElib_FreeReply(&reply);
		DEBUG(("decrupt_rsa_cleanup done\n"));
	
	}
	return errorcode;
}

//redeem the ticket of keys from sitting module
static void redeem_ticket(const unsigned char *ptr, M_Word len, unsigned char task, M_ByteBlock * result)
{
	M_Command cmd;
	M_Reply reply;
	M_ByteBlock ticket;
	M_Word rc;
	M_ByteBlock keyhash;
	M_Word sep;
	//init the return result
	result->ptr=malloc(1);
	result->len=1;
	if(result->ptr==NULL){
		goto redeem_cleanup;
	}
	result->ptr[0]=2;	
	getnexttoken(ptr, 0, len, &sep, &keyhash);
	if(keyhash.ptr==NULL){
		DEBUG(("Unable to get the key hash for redeem"));
		result->ptr[0]=3;
		goto redeem_cleanup;
	}
	printHex("keyhash", keyhash.ptr, keyhash.len);	
	/* Restore ticket data */
	dup_data(ptr+41, len-41, &ticket);
	
	/* Redeem the ticket */
	memset(&cmd, 0, sizeof(cmd));
	memset(&reply, 0, sizeof(reply));
	cmd.cmd = Cmd_RedeemTicket;
	cmd.args.redeemticket.ticket = ticket;

	if((rc = signers_transact(&cmd, &reply)) != Status_OK){
		result->ptr[0]=4;
		die("signers_transact (RedeemTicket)\n", rc);		
	}else{
		switch(task){
			case see_ticket_rsa:
				result->ptr[0]=addLoadedKey(keyhash.ptr, HASHLEN,reply.reply.redeemticket.obj, RSA);			
				break;
			case see_ticket_des3:
				result->ptr[0]=addLoadedKey(keyhash.ptr, HASHLEN,reply.reply.redeemticket.obj, DES3);
				break;
			case see_ticket_aes:
				result->ptr[0]=addLoadedKey(keyhash.ptr, HASHLEN,reply.reply.redeemticket.obj, AES);
				break;
			case see_ticket_des3_new:
				result->ptr[0]=addLoadedKey(keyhash.ptr, HASHLEN,reply.reply.redeemticket.obj, DES3);
				break;
			case see_ticket_aes_new:
				result->ptr[0]=addLoadedKey(keyhash.ptr, HASHLEN,reply.reply.redeemticket.obj, AES);
				break;	
			default:
				DEBUG(("Store key type new defined =%d\n", task));
		}
	}
	DEBUG(("Redeemed ticket\n"));
	/* Nothing is sent back to the host for this job */
	free(keyhash.ptr);
redeem_cleanup:	
	SEElib_FreeCommand(&cmd);
	SEElib_FreeReply(&reply);
}

//decrypt data using symetric key
static void decrypt_sym(const unsigned char *ptr, M_Word  len, M_KeyID sym_key, see_key_type t, M_ByteBlock * result) 
{

  M_Command cmd;
  M_Reply reply;
  M_CipherText cipher_text;
  M_ByteBlock data;
  M_Word rc;
  result->ptr=NULL;
  result->len=0;
// Restore contents of M_CipherText 
  dup_data(ptr, len, &data);
  cipher_text.data.generic64.cipher=data;
  
  if(t==DES3){
	cipher_text.mech = Mech_DES3mECBpPKCS5;
  }else{
	if(t==AES){
		cipher_text.mech= Mech_RijndaelmECBpPKCS5;
	}else {
		DEBUG(("No store key specified\n"));
	}
  }
  
  // Decrypt cipher text 
  memset(&cmd, 0, sizeof(cmd));
  memset(&reply, 0, sizeof(reply));
  cmd.args.decrypt.key = sym_key;
  cmd.args.decrypt.reply_type = PlainTextType_Bytes;
  cmd.cmd = Cmd_Decrypt;
  cmd.args.decrypt.cipher = cipher_text;
  if((rc = signers_transact(&cmd, &reply)) != Status_OK){
    die("signers_transact (decrypt)\n", rc);
  }
  else{
	  // copy the plaintext result (an M_byteblock) then zero it in the reply so that SEElib_freereply does not free it /
	  *result = reply.reply.decrypt.plain.data.bytes.data;
	  
	  if(result->ptr==NULL){
		DEBUG(("Error:failed to do symmetric decrypt:\n"));
	  }
	  else
		memset(&reply.reply.decrypt.plain.data.bytes.data, 0, sizeof(M_ByteBlock));
  }
  SEElib_FreeCommand(&cmd);
  SEElib_FreeReply(&reply);
 
}

//encrypt a data block using stored symmetric key
static void encrypt_sym(const unsigned char *ptr, M_Word  len, M_KeyID sym_key, see_key_type t, M_ByteBlock * result)
{
  
	M_CipherText *cipher=NULL;
	M_Command cmd;
	M_Reply reply;
	M_ByteBlock data;
	M_Word rc;
	result->len=0;
	result->ptr=NULL;
	memset(&cmd,0,sizeof(cmd));
	memset(&reply, 0, sizeof(reply));

	cmd.cmd = Cmd_Encrypt;
	cmd.args.encrypt.key = sym_key;  
	if(t==DES3){
		cmd.args.encrypt.mech = Mech_DES3mECBpPKCS5;
	}else
	if(t==AES){
		cmd.args.encrypt.mech = Mech_RijndaelmECBpPKCS5;
	}
	cmd.args.encrypt.plain.type = PlainTextType_Bytes;
	dup_data(ptr, len, &data);
	cmd.args.encrypt.plain.data.bytes.data =data;
	rc = signers_transact(&cmd, &reply);
	if(rc==Status_OK) {
		cipher= &reply.reply.encrypt.cipher;  
		result->len = cipher->data.generic64.cipher.len;
		result->ptr = malloc(result->len);
		if (result->ptr == NULL||cipher->data.generic64.cipher.ptr==NULL){
			die("marshal cipher text memory allocation", 0);
		}
		else
			memcpy(result->ptr , cipher->data.generic64.cipher.ptr, cipher->data.generic64.cipher.len);
	}
	SEElib_FreeCommand(&cmd);
	SEElib_FreeReply(&reply);
}


 static void e2ee_verify_password(const unsigned char *ptr, M_Word  len, M_ByteBlock * result)
 {
/*
error code definitions:
0: password is verified
1: password is not verified
2: memory allocation fails
3: get hash fails
4: Decryption of epin fails
5: Decryption of spin fails
6: Transaction key not found
7: Store key not found
8: Big number allocation failed
9: decrypt command not run succesfully
10: decrypted epin length not sufficient
11: challenge not found
12: challenge code is null or length not correct
*/  
	M_ByteBlock epin;
	M_ByteBlock userid;
	M_ByteBlock currentSPin;
	M_ByteBlock challenge;
	//M_ByteBlock otherparams;
	M_ByteBlock clearpassword;
	M_ByteBlock hashuserid;
	unsigned char * hashcomb=NULL;
	M_ByteBlock decyrptedspin;
	
	M_Word sep1, sep2; //seperator locations
	unsigned char error_code=0;
	M_Word match=FALSE;
	
	M_ByteBlock transkeyhash;
	M_ByteBlock storekeyhash;
	see_key transkey;
	see_key storekey;
	M_Word foundkey;
	//define default value
	result->ptr=NULL;
	result->len=0;
	M_Word decryptrsarc=0;
	/*umarshal the given data */
	
	getnexttoken(ptr, 0, len, &sep1, &transkeyhash);
	getnexttoken(ptr, sep1+1, len, &sep2, &storekeyhash);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &epin);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &currentSPin);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &userid);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &challenge);
	//sep1=sep2;
	//getnexttoken(ptr, sep1+1, len, &sep2, &otherparams);
	

	foundkey=getLoadedKey(transkeyhash.ptr, transkeyhash.len, &transkey);
	if(foundkey==FALSE){
		DEBUG(("RSA private key not found"));
		free(transkeyhash.ptr);
		free(storekeyhash.ptr);
		free(epin.ptr);
		free(currentSPin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		error_code=7;
		goto verify_password_cleanup;
	}
	
	foundkey=getLoadedKey(storekeyhash.ptr, storekeyhash.len, &storekey);
	if(foundkey==FALSE){
		DEBUG(("Symmetric private key not found"));
		free(transkeyhash.ptr);
		free(storekeyhash.ptr);
		free(epin.ptr);
		free(currentSPin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		error_code=8;
		goto verify_password_cleanup;
	}
	free(transkeyhash.ptr);
	free(storekeyhash.ptr);
	// get  pin hash from stored pin	
	decryptrsarc=decrypt_rsa(transkey.keyid, epin.ptr, epin.len, challenge.ptr, challenge.len, USERPINLEN, &clearpassword);
	if(clearpassword.ptr==NULL){
		DEBUG(("Error:Failed to decrypt user input pin\n"));
		error_code=7+decryptrsarc;
		free(epin.ptr);
		free(currentSPin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		goto verify_password_cleanup;
	}
	
	gethash(userid.ptr, userid.len, &hashuserid);   
	if(hashuserid.ptr==NULL){
		DEBUG(("Error:failed to get hash of userid\n"));
		error_code=3;
		free(epin.ptr);
		free(currentSPin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		free(clearpassword.ptr);
		goto verify_password_cleanup;
	}
	hashcomb=malloc(40);
	if(hashcomb!=NULL){ 
		//pack the pin hash and user id hash
		memcpy(hashcomb, clearpassword.ptr, 20);
		memcpy(hashcomb+20, hashuserid.ptr, 20);
	//clear the hashes and keep the combinnation 
	}else{
		DEBUG(("Error:failed to allocate hashcomb"));
		error_code = 2; 
		free(epin.ptr);
		free(currentSPin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		free(clearpassword.ptr);
		free(hashuserid.ptr);
		goto verify_password_cleanup;
	}
	//printHex("Sendingin ptr", currentSPin.ptr, currentSPin.len);
	decrypt_sym(currentSPin.ptr, currentSPin.len, storekey.keyid, storekey.keytype, &decyrptedspin);	
	if(decyrptedspin.ptr==NULL||decyrptedspin.len!=40){
		DEBUG(("Error:Spin decryption failed, Password is not verified.\n"));
		error_code=5;
		free(epin.ptr);
		free(currentSPin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		free(clearpassword.ptr);
		free(hashuserid.ptr);
		free(hashcomb);
		goto verify_password_cleanup;
	}else{
	//compare the decrypted spin and given pin
		match =is_same_bytes(decyrptedspin.ptr, hashcomb, 40);	
		if(match==TRUE){
			DEBUG(("Password is verified.\n"));
			error_code=0;
		}
		else{
			DEBUG(("Error:Password is not correct.\n"));
			error_code=1;
		}
		free(epin.ptr);
		free(currentSPin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		free(clearpassword.ptr);
		free(hashuserid.ptr);
		free(hashcomb);
		free(decyrptedspin.ptr);
	}

verify_password_cleanup: //return the byteblock with error code embedded
	if((result->ptr=malloc(1))!=NULL){
			result->len=1;
			result->ptr[0]=error_code;
	}
	
 }




 static void e2ee_change_password (const unsigned char *ptr, M_Word  len, M_ByteBlock * result )
{
/*
error codes definitions:
1: memeory allocation fails
2: decryption of Spin fails
3: compute hash fails
4: old password is not verified
5: new password is found in history
6: decryption of Epin fails
7: Trasaction key not found
8: Store key not found
9: Big number allocation failed
10: decrypt command not run succesfully
11: decrypted epin length not sufficient
12: challenge not found
13: challenge code is null or length not correct
*/

	M_Word sep1, sep2;
	M_ByteBlock epin;
	M_ByteBlock currentSpin;
	M_ByteBlock  userid;
	M_ByteBlock challenge;
	//unsigned char ** pinhis;
	M_ByteBlock *pinhis=NULL;
	M_ByteBlock clearpassword;
	//M_ByteBlock temppin;
	unsigned char *  oldpin=NULL;
	unsigned char *  newpin=NULL;
	M_ByteBlock hashuserid;
	M_ByteBlock decryptedspin;
	M_ByteBlock clearhispin;
	unsigned char * hashcomb1=NULL;
	unsigned char * hashcomb2=NULL;
	M_Word hissize;
	M_Word hispinlen;
	M_Word i;
	M_ByteBlock transkeyhash;
	M_ByteBlock storekeyhash;
	see_key transkey;
	see_key storekey;
	M_Word foundkey;
	M_Word decryptrsarc=0;
	unsigned char error_code=0;
	//give default value to result

	result->len=0;
	result->ptr=NULL;
	
	//get the pin history size and length for each pin
	hissize=ptr[0];
	hispinlen=ptr[1];
		
	//unwrap command can get the parameters
	getnexttoken(ptr, 2, len, &sep1, &transkeyhash);	
	getnexttoken(ptr, sep1+1, len, &sep2, &storekeyhash);	
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &epin);	
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &currentSpin);
	
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &userid);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &challenge);
	sep1=sep2;
	
	if(hissize>0&&hissize<=16)
		pinhis=malloc(hissize*sizeof(M_ByteBlock));
	if(hissize>0&&pinhis==NULL) {
		DEBUG(("Failed to allocate pinhis"));
		free(transkeyhash.ptr);
		free(storekeyhash.ptr);
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		error_code=1;
		goto change_password_cleanup;
	}
	
	M_Word finalsize=0;
	for (i=0; i<hissize; i++){
		//retrive the list of history password
		getnexttoken(ptr, sep1+1, len, &sep2, &pinhis[finalsize]);
		sep1=sep2;
		if(pinhis[finalsize].ptr!=NULL){
			finalsize++;
		}
	}
	hissize=finalsize;
	
	
	foundkey=getLoadedKey(transkeyhash.ptr, transkeyhash.len, &transkey);
	if(foundkey==FALSE){
		DEBUG(("RSA private key not found"));
		free(transkeyhash.ptr);
		free(storekeyhash.ptr);
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		error_code=7;
		goto change_password_cleanup;
	}
	
	foundkey=getLoadedKey(storekeyhash.ptr, storekeyhash.len, &storekey);
	if(foundkey==FALSE){
		DEBUG(("Symmetric key not found"));
		free(transkeyhash.ptr);
		free(storekeyhash.ptr);
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		error_code=8;
		goto change_password_cleanup;
	}
	free(transkeyhash.ptr);
	free(storekeyhash.ptr);
	
	//encrypt spin
	decrypt_sym(currentSpin.ptr, currentSpin.len, storekey.keyid, storekey.keytype, &decryptedspin);
	
	if( decryptedspin.ptr==NULL ){
		DEBUG(("Decrypt Spin failed\n"));
		error_code=2;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		goto change_password_cleanup;
	}
	
	decryptrsarc = decrypt_rsa(transkey.keyid, epin.ptr, epin.len, challenge.ptr, challenge.len, USERPINLEN*2, &clearpassword);
	//do a check here
	if(clearpassword.ptr==NULL){
		DEBUG(("Error:user pins decryption failed\n"));	
		error_code=8+decryptrsarc;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		goto change_password_cleanup;
	}
	
	oldpin=malloc(USERPINLEN);
	if(oldpin!=NULL){
		memcpy(oldpin, clearpassword.ptr, USERPINLEN);
		//printHex("oldpin", oldpin, USERPINLEN);
	}else{
		DEBUG(("failed to allocate memeory for oldpin\n"));	
		error_code=1;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		free(clearpassword.ptr);
		goto change_password_cleanup;
	}
	
	newpin=malloc(USERPINLEN);
	if(newpin!=NULL){
		memcpy(newpin,clearpassword.ptr+USERPINLEN, USERPINLEN);
		//printHex("newpin", newpin, USERPINLEN);
	}else{
		DEBUG(("failed to allocate memeory for newpin\n"));	
		error_code=1;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		free(clearpassword.ptr);
		free(oldpin);
		goto change_password_cleanup;
	}
	
	gethash(userid.ptr, userid.len, &hashuserid);
	if(hashuserid.ptr==NULL){
		DEBUG(("failed to get hash of userid\n"));	
		error_code=3;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		free(clearpassword.ptr);
		free(oldpin);
		free(newpin);
		goto change_password_cleanup;
	}
	hashcomb1=(unsigned char *)malloc(40);
	if(hashcomb1!=NULL){
		//pack the pin hash and user id hash
		memcpy(hashcomb1, oldpin, 20);
		memcpy(hashcomb1+20, hashuserid.ptr, 20);
	}else {
		DEBUG(("failed allocate memeory for hashcomb1\n"));	
		error_code=1;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		free(clearpassword.ptr);
		free(oldpin);
		free(newpin);
		free(hashuserid.ptr);
		goto change_password_cleanup;
	}
	hashcomb2=(unsigned char *)malloc(40);
	if(hashcomb2!=NULL){
		//pack the pin hash and user id hash
		memcpy(hashcomb2, newpin, 20);
		memcpy(hashcomb2+20, hashuserid.ptr, 20);
	}else {
		DEBUG(("failed allocate memeory for hashcomb2s\n"));	
		error_code=1;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		free(clearpassword.ptr);
		free(oldpin);
		free(newpin);
		free(hashuserid.ptr);
		free(hashcomb1);
		goto change_password_cleanup;
	}

	if(is_same_bytes(decryptedspin.ptr, hashcomb1, 40)==FALSE){
		DEBUG(("old password not verified\n"));
		error_code=4;
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		free(clearpassword.ptr);
		free(oldpin);
		free(newpin);
		free(hashuserid.ptr);
		free(hashcomb1);
		free(hashcomb2);
		goto change_password_cleanup;
	}else{
	    DEBUG(("old password is verified\n"));
		
		for(i=0;i<hissize&&pinhis[i].ptr!=NULL; i++){
			//printHex("hispin", pinhis[i].ptr, hispinlen/2);
			decrypt_sym(pinhis[i].ptr, hispinlen/2, storekey.keyid, storekey.keytype, &clearhispin);
			if( clearhispin.ptr==NULL ){
				//old password is melformed, treat as pin not found
				continue;
			}
			if(is_same_bytes(clearhispin.ptr, hashcomb2, 40)==TRUE){
				free(clearhispin.ptr);
				DEBUG(("new password is found in history\n"));
				error_code=5;
				free(epin.ptr);
				free(currentSpin.ptr);
				free(userid.ptr);
				free(challenge.ptr);
				if(pinhis!=NULL){
					for(i=0; i<hissize;i++)
						free(pinhis[i].ptr);
					free(pinhis);
				}
				free(decryptedspin.ptr);
				free(clearpassword.ptr);
				free(oldpin);
				free(newpin);
				free(hashuserid.ptr);
				free(hashcomb1);
				free(hashcomb2);
				goto change_password_cleanup;
			}
			else
				free(clearhispin.ptr);
		}
		encrypt_sym(hashcomb2, 40, storekey.keyid, storekey.keytype, result);
		free(epin.ptr);
		free(currentSpin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		if(pinhis!=NULL){
			for(i=0; i<hissize;i++)
				free(pinhis[i].ptr);
			free(pinhis);
		}
		free(decryptedspin.ptr);
		free(clearpassword.ptr);
		free(oldpin);
		free(newpin);
		free(hashuserid.ptr);
		free(hashcomb1);
		free(hashcomb2);
	}

change_password_cleanup:		
		if(error_code>0)
		{
			if((result->ptr=malloc(1))!=NULL){
				result->len=1;
				result->ptr[0]=error_code;
			}
		}
}


static void e2ee_reset_password (const unsigned char *ptr, M_Word  len, M_ByteBlock * result )
{
 /*
	Error code definition
	1: Decrypt epin fails
	2: Retrieve hash fails
	3: Memeory allocation fails
	4: Encrypt new Spin fails
	5: Trasaction key not found
	6: Store key not found
	8: Big number allocation failed
	9: decrypt command not run succesfully
	10: decrypted epin length not sufficient
	11: challenge not found
	12: challenge code is null or length not correct
 */
 
	M_ByteBlock epin;
	M_ByteBlock userid;
	M_ByteBlock challenge;
	//M_ByteBlock otherparams;
	M_ByteBlock pintoreset;
	M_ByteBlock hashuserid;
	unsigned char * hashcomb=NULL;
	M_Word error_code=0;
	M_ByteBlock storekeyhash;
	M_ByteBlock transkeyhash;
	see_key transkey;
	see_key storekey;
	M_Word decryptrsarc=0;
	M_Word sep1, sep2;
	M_Word foundkey;
	result->ptr=NULL;
	result->len=0;
	
	/*umarshal the given data */
	getnexttoken(ptr, 0, len, &sep1, &transkeyhash);
	getnexttoken(ptr, sep1+1, len, &sep2, &storekeyhash);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &epin);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &userid);
	sep1=sep2;
	getnexttoken(ptr, sep1+1, len, &sep2, &challenge );
	//sep1=sep2;
	//getnexttoken(ptr, sep1+1, len, &sep2, &otherparams);
	
	
	foundkey=getLoadedKey(transkeyhash.ptr, transkeyhash.len, &transkey);
	if(foundkey==FALSE){
		DEBUG(("RSA private key not found"));
		free(transkeyhash.ptr);
		free(storekeyhash.ptr);
		free(epin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		error_code=5;
		goto reset_password_cleanup;
	}
	
	foundkey=getLoadedKey(storekeyhash.ptr, storekeyhash.len, &storekey);
	if(foundkey==FALSE){
		DEBUG(("Symmetric private key not found"));
		free(transkeyhash.ptr);
		free(storekeyhash.ptr);
		free(epin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		error_code=6;
		goto reset_password_cleanup;
	}
	free(transkeyhash.ptr);
	free(storekeyhash.ptr);
	//get  pin hash
	decryptrsarc= decrypt_rsa(transkey.keyid, epin.ptr, epin.len, challenge.ptr, challenge.len, USERPINLEN, &pintoreset);
	if(pintoreset.ptr==NULL){
		DEBUG(("Failed to decrypt reset pin\n"));
		
		free(epin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		error_code=7+decryptrsarc;
		goto reset_password_cleanup;
	}
	pintoreset.len=USERPINLEN; 
	gethash(userid.ptr, userid.len, &hashuserid);    
	if(hashuserid.ptr==NULL){
		free(epin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		free(pintoreset.ptr);
		error_code=2;
		goto reset_password_cleanup;
	}
	if(pintoreset.ptr!=NULL&&(hashcomb=malloc(40))!=NULL){
		//pack the pin hash and user id hash
		memcpy(hashcomb, pintoreset.ptr, 20);
		memcpy(hashcomb+20, hashuserid.ptr, 20);
		
		encrypt_sym(hashcomb, 40, storekey.keyid, storekey.keytype, result);
		if(result->ptr==NULL)
			error_code=4;
		free(epin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		free(pintoreset.ptr);
		free(hashuserid.ptr);
		free(hashcomb);
	}else{
		free(epin.ptr);
		free(userid.ptr);
		free(challenge.ptr);
		//free(otherparams.ptr);
		free(pintoreset.ptr);
		free(hashuserid.ptr);
		error_code=3;
		DEBUG(("error:failed to allocate memory for hahscomb or get hash of userid"));
		
	}

reset_password_cleanup:	

	if(error_code>0){
		if((result->ptr=malloc(1))!=NULL){
			result->len=1;
			result->ptr[0]=error_code;
		}
	}
 }

//unwrap cammnd and encrypt given clear password
static void e2ee_encrypt_password(const unsigned char *ptr, M_Word  len, M_ByteBlock * result )
{
/*
	1: Get pin hash fails
	2: Get userid hash fails
	3: Memory allocation fails
	4: encrypt new Spin fails
	5: Store key not found
*/ 
 
	M_Word sep0,  sep1, sep2;
	M_ByteBlock pin;
	M_ByteBlock userid;
	//M_ByteBlock otherparams;
	M_ByteBlock hashpin;
	M_ByteBlock hashuserid;
	M_ByteBlock hashkey;
	see_key currentkey;
    unsigned char * hashcomb=NULL;	
	M_Word loadkeyresult=FALSE;
	M_Word errorcode= 0;
	result->ptr=NULL;
	result->len=0;
	
	//get keyhash
	getnexttoken(ptr,0,len, &sep0, &hashkey);
	//get user pin
    getnexttoken(ptr,sep0+1,len, &sep1, &pin);
	//get user id
	getnexttoken(ptr, sep1+1, len, &sep2, &userid);
	//get other parameters if any
	//getnexttoken(ptr, sep2+1, len, &sep3, &otherparams);
	//get user pin hash
	
	loadkeyresult= getLoadedKey(hashkey.ptr, hashkey.len, &currentkey);
	if(loadkeyresult==FALSE){
		DEBUG(("Unable to find the loaded symmetric key"));
		clearCredentials(pin.ptr, pin.len);
		free(hashkey.ptr);
		free(pin.ptr);
		free(userid.ptr);
		errorcode=5;
		//free(otherparams.ptr);
	}else{
		free(hashkey.ptr);
		DEBUG(("found the loaded key:%d\n", currentkey.keyid));
		gethash(pin.ptr, pin.len,&hashpin);
		if(hashpin.ptr==NULL){
			clearCredentials(pin.ptr, pin.len);
			free(pin.ptr);
			free(userid.ptr);
			errorcode=1;
			//free(otherparams.ptr);
		}else{
			//get userid hash
			gethash(userid.ptr, userid.len, &hashuserid);
			//printHex("hashuserid", hashuserid.ptr, 20);
			if(hashuserid.ptr==NULL){
				clearCredentials(pin.ptr, pin.len);
				free(pin.ptr);
				free(userid.ptr);
				//free(otherparams.ptr);
				free(hashpin.ptr);
				errorcode=2;
			}else{
				hashcomb=malloc(40);
				if(hashcomb!=NULL){
					//pack the pin hash and user id hash
					memcpy(hashcomb, hashpin.ptr, 20);
					memcpy(hashcomb+20, hashuserid.ptr, 20);
					//get the encrypted hash
					encrypt_sym(hashcomb, 40, currentkey.keyid, currentkey.keytype, result);
					if(result->ptr==NULL)
						errorcode=4;
					clearCredentials(pin.ptr, pin.len);
					free(pin.ptr);
					free(userid.ptr);
					//free(otherparams.ptr);
					free(hashpin.ptr);
					free(hashcomb);
					free(hashuserid.ptr);
				}
				else{
					clearCredentials(pin.ptr, pin.len);
					free(pin.ptr);
					free(userid.ptr);
					//free(otherparams.ptr);
					free(hashpin.ptr);
					free(hashcomb);
					free(hashuserid.ptr);
					errorcode=3;
					DEBUG(("Failed to allocated hashcomb\n"));
				}
			}
			//clear the hashes and keep the combinnation 
			//printHex("rsult", result->ptr, result->len);
		}
	}
	if(errorcode>0&&result->ptr==NULL){
		result->ptr=malloc(1);
		result->ptr[0]=errorcode;
		result->len= 1;
	}
}


//unwrap command and re-encrypt given clear password with new key
static void e2ee_get_new_encrypt_password(const unsigned char *ptr, M_Word  len, M_ByteBlock * result)
{
  /*
  encrypt new password
  1: old store key not found
  2: new store key not found 
  3: decrypt old Spin fails
  4: Encrypt new Spin fails
  */
	M_Word sep1, sep2;
	M_ByteBlock pin;
	//M_ByteBlock otherparams;
	M_ByteBlock hashpin;
	M_Word foundkey;
	
	M_ByteBlock storekeyhash1;
	M_ByteBlock storekeyhash2;
	see_key storekey1;
	see_key storekey2;
	result->ptr=NULL;
	result->len=0;
	M_Word errorcode=0;
	//
	getnexttoken(ptr,0,len, &sep1, &storekeyhash1);
	getnexttoken(ptr, sep1+1, len, &sep2, &storekeyhash2);

	sep1=sep2;
	//get encrypt pin	
    getnexttoken(ptr,sep1+1,len, &sep2, &pin);
	//sep1=sep2;
	//getnexttoken(ptr, sep1+1, len, &sep2, &otherparams);
	
	foundkey=getLoadedKey(storekeyhash1.ptr, storekeyhash1.len, &storekey1);
	if(foundkey==FALSE){
		DEBUG(("Old symmetric key  not found"));
		free(storekeyhash1.ptr);
		free(storekeyhash2.ptr);
		free(pin.ptr);
		errorcode=1;
		goto e2ee_new_encrypt_password_end;
	}
	
	foundkey=getLoadedKey(storekeyhash2.ptr, storekeyhash2.len, &storekey2);
	if(foundkey==FALSE){
		DEBUG(("New symmetric key not found"));
		free(storekeyhash1.ptr);
		free(storekeyhash2.ptr);
		free(pin.ptr);
		errorcode=2;
		goto e2ee_new_encrypt_password_end;
	}
	free(storekeyhash1.ptr);
	free(storekeyhash2.ptr);
	
	
	//get user pin hash
	
	decrypt_sym(pin.ptr, pin.len, storekey1.keyid, storekey1.keytype, &hashpin);
	
	if(hashpin.ptr==NULL){
		DEBUG(("Failed to get clear pin using old store key\n"));
		free(pin.ptr);
		errorcode=3;
		//free(otherparams.ptr);
	}else{
	//printHex("oldpin", hashpin.ptr, 40);
		encrypt_sym(hashpin.ptr, 40, storekey2.keyid, storekey2.keytype, result);
		if(result->ptr==NULL)
			errorcode=4;
		free(pin.ptr);
		//free(otherparams.ptr);
		free(hashpin.ptr);
	}
e2ee_new_encrypt_password_end: 
	if(errorcode>0&&result->ptr==NULL)
	{
		result->ptr=malloc(1);
		result->ptr[0]=errorcode;
	}
}

M_ByteBlock process_job(const unsigned char *buffer, int len)
{
/* This function receives what was initially placed in the seejob
   command on the host. The first byte is examined and then the 
   buffer is passed on to the appropriate place for unmarshaling 
   and processing.
*/

{
    M_Command dbg_cmd;
    M_Reply dbg_reply;
    memset(&dbg_cmd, 0, sizeof(dbg_cmd));
    memset(&dbg_reply, 0, sizeof(dbg_reply));
    dbg_cmd.cmd = Cmd_GetWorldSigners;
    if (SEElib_Transact(&dbg_cmd, &dbg_reply) == Status_OK) {
      int si;
      printf("GetWorldSigners returned %d sigs\n", dbg_reply.reply.getworldsigners.n_sigs);
      for (si = 0; si < dbg_reply.reply.getworldsigners.n_sigs; si++) {
        printHex("WorldSigner hash", 
          (unsigned char*)dbg_reply.reply.getworldsigners.sigs[si].hash.bytes, 
          sizeof(M_KeyHash));
      }
    }
    SEElib_FreeReply(&dbg_reply);
  }
  M_ByteBlock result;
  unsigned char task;
  result.ptr = NULL;
  result.len = 0;
 
  
  /* Check the buffer and len are valid */
  if (buffer == NULL || len < 1){
    die("process job - invalid input buffer", 0);
	return result;
  }
  
  
  task = *buffer;
  buffer++;  len--;

  if(task==see_e2ee_activate){
	//do activation
	activate(buffer, len, &result);
	return result;
  }
  else if(task==see_e2ee_check_status){
	//check activation status
	get_status(&result);
	return result;
  }else{
	if(task== see_e2ee_version){
		get_version(&result);
		return result;
	}
  }
  
  if(activation_status==ACTIVATED||activation_status==EVALUATION)
  switch (task)
  {
  // First byte tells us what job it is. Pass on the rest of the buffer 
	 case see_e2ee_verify_password:
		DEBUG(("seejob received (verify pin)\n"));
		e2ee_verify_password(buffer, len, &result);

		break;
	case see_e2ee_change_password:
		DEBUG(("seejob received (change pin)\n"));   
		e2ee_change_password(buffer, len, &result);

		break;
	case see_e2ee_reset_password:
		DEBUG(("seejob received (reset pin)\n"));
		/* Check session key has been decrypted first */
		e2ee_reset_password(buffer, len, &result);
		break;

	case see_e2ee_encrypt_password:
    DEBUG(("seejob received (encrypt pin)\n"));
    
    //check for availability of store key first 
	 e2ee_encrypt_password(buffer, len, &result);
    break;


	case see_e2ee_check_keyload:
		DEBUG(("seejob received (check key load)\n"));
		check_key_loaded(buffer, len, &result);
		break;

	case see_ticket_rsa:
		DEBUG(("seejob received (rsa ticket)\n"));
		// Pass in the rest of buffer 
		redeem_ticket(buffer, len, task, &result);
		break;
	case see_ticket_des3:
		DEBUG(("seejob received (des3 ticket)\n"));

		/* Pass in the rest of buffer */
		redeem_ticket(buffer, len, task, &result);
		break;
	case see_ticket_aes:
		DEBUG(("seejob received (aes ticket)\n"));
		redeem_ticket(buffer, len, task, &result);
		break;

	case see_ticket_des3_new:
		DEBUG(("seejob received (new des3 ticket)\n"));
		/* Pass in the rest of buffer */
		redeem_ticket(buffer, len, task, &result);
		break;
	case see_ticket_aes_new:
		DEBUG(("seejob received (new aes ticket)\n"));
		redeem_ticket(buffer, len, task, &result);
		break;	
	case see_e2ee_new_encrypt_password:
		DEBUG(("seejob received (encrypt pin)\n"));
		//check for availability of store key first 
		e2ee_get_new_encrypt_password(buffer, len, &result);
		break;	
	default:
		DEBUG(("Unknown command\n"));
		break;
  }  
  return (result);
}


