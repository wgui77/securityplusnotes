
SncE2EECipherSEE.java

package com..e2ee;

import com..e2ee.base.*;
import com.ncipher.provider.km.*;
import com.ncipher.nfast.*;
import com.ncipher.nfast.connect.*;
import com.ncipher.nfast.marshall.*;
import com.ncipher.km.nfkm.*;
import com.ncipher.jutils.*;
import com.ncipher.nfast.connect.utils.*;
import java.lang.*;
import java.text.*;
import java.io.*;
import java.util.*;

import com..base.log.*;
import com..license.LicenseMaster;

import java.math.*;

import com.ncipher.nfast.*;
import com.ncipher.nfast.connect.*;
import com.ncipher.nfast.marshall.*;
import com.ncipher.km.nfkm.*;
import com.ncipher.jutils.*;
import com.ncipher.jnfopt.*;
import com.ncipher.nfast.*;
import com.ncipher.see.hostside.*;
import com.ncipher.km.marshall.*;

public class SncE2EEnCipherSEE implements ISncE2EE {
    private static final String E2EESeeVersion = "0.1.0.3.3";
    private SncE2EEConfig conf = null;

    public SncLogManager logger = null;
    private static NFConnection conn = null;
    private static M_KeyID seeworldid = null;
    private static SEEWorld seeworld = null;

    private static SecurityWorld sworld = null;
    // RSA key specs

    private static Hashtable<String, M_KeyID> loadedkeys;

    private M_KeyID rsaprivkeyid = null;
    private String rsaprivident = null;

    private M_KeyID rsapubkeyid = null;
    private String rsapubident = null;
    // des3 key specs
    private M_KeyID des3keyid = null;
    private String des3ident = null;
    // AES key specs
    private M_KeyID aeskeyid = null;
    private String aesident = null;

    private String trans_key_appname = "simple";
    private String store_key_appname = "simple";
    // current key id
    private M_KeyID storekeyid = null;

    private byte[] storekeyhash = null;
    private byte[] transkeyhash = null;

    private boolean usingDES3 = false;
    private boolean usingAES = false;

    // 	private static Reference.Bool debugRef = new Reference.Bool(true); | NEW CS5: debugRef removed -- debug logging now done via csadmin log get

    private static final byte SEP = 16;
    private static Module[] modules = null;
    private static M_KeyID[] seeworldids = null;
    private static SEEWorld[] seeworlds = null;
    private static int moduleids[] = null;
    private static int module_no = 0;
    // 	private static String userdatafile=null; | NEW CS5: userdatafile removed -- no buffer/userdata loading needed

    private static Hashtable licenses = null;
    private static int eval_execution_count = 0;
    private static boolean EVALUATION_MODE = false;

    private static final int MAX_EVALUATION_COUNT = 100000;
    private static String see_evaluation_esns = "";

    private String confFile = null;
    private String cachedPublicKeyString = null;

    private static boolean usingAllHSM = true;

    private static int[] activeModuleList = null;

    private static String initErrorMessage = null;
    private static boolean resetDone = false;
    private static boolean initialized = false;
    private static final String E2EE_SEE_PUBLISH_NAME = "e2ee_see";

    static {
        try{
			sworld = new SecurityWorld(new ConsoleCallBack());
			//conn=new NFConnection(NFConnection.flags_Privileged);
			conn=sworld.getConnection();
			loadedkeys= new Hashtable <String,M_KeyID>();
			//sworld.setConnection(conn);
        }catch(Exception e){
            //logger.error("Init conn  & security world error: "+e.toString());
            e.printStackTrace();
			initErrorMessage="Init conn  & security world error: "+e.toString();
			//System.err.println("Init conn  & security world error: "+e.toString());
        }
    }

    public boolean initialize(String confFile, String otherParams) {
        // validate the configuration file path
        if (confFile == null || confFile.trim().equals("")) {
            System.err.println("Invalid configuration file path: configuration can not be null or empty.");
            return false;
        }
        if (!(new File(confFile)).exists()) {
            System.err.println("Invalid configuration file path: File not found.");
            return false;
        }
        this.confFile = confFile;
        conf = SncE2EEConfig.getInstance(confFile);
        //provider = conf.getProperty(SncSEECode.JCE_PROVIDER);
        logger = SncLogManager.getInstance(conf.getProperty(SncSEECode.LOG_FILENAME));
        logger.setLevel(conf.getProperty(SncSEECode.LOG_LEVEL));
        if (initErrorMessage != null)
            logger.error(initErrorMessage);
        logger.info("Initializing  End to End Encryption SEE Cipher v" + E2EESeeVersion);

        //provider = conf.getProperty(SncSEECode.JCE_PROVIDER);
        //logger.debug("JCE Provider: "+provider); 
		// boolean debugval= "true".equals(conf.getProperty("DEBUG_ENABLED"));
		// debugRef= new Reference.Bool(debugval);
        // CS5: debugRef removed
        String transkeytype = conf.getProperty(SncSEECode.TRANS_KEY_TYPE);
        String storekeytype = conf.getProperty(SncSEECode.STORE_KEY_TYPE);
        if (storekeytype.equals("DES3")) {
            usingDES3 = true;
        } 
        else 
            if (storekeytype.startsWith("AES")) {
            usingAES = true;
        }
        logger.debug("Store key type: " + storekeytype);
        logger.debug("Trans key type: " + transkeytype);
        if (conf.getProperty(SncSEECode.TRANS_KEY_APPNAME) != null && !conf.getProperty(SncSEECode.TRANS_KEY_APPNAME).equals(""))
            trans_key_appname = conf.getProperty(SncSEECode.TRANS_KEY_APPNAME);

        if (conf.getProperty(SncSEECode.STORE_KEY_APPNAME) != null && !conf.getProperty(SncSEECode.STORE_KEY_APPNAME).equals(""))
            store_key_appname = conf.getProperty(SncSEECode.STORE_KEY_APPNAME);
        logger.debug("Store key app name: " + store_key_appname);
        logger.debug("Trans key app name: " + trans_key_appname);

        rsaprivident = conf.getProperty(SncSEECode.TRANS_KEY_ALIAS);
        rsapubident = conf.getProperty(SncSEECode.TRANS_KEY_ALIAS);

        logger.debug("Trans key ident: " + rsapubident);
        if (usingDES3)
            des3ident = conf.getProperty(SncSEECode.STORE_KEY_ALIAS);
        if (usingAES)
            aesident = conf.getProperty(SncSEECode.STORE_KEY_ALIAS);
        logger.debug("Store key ident: " + (des3ident != null ? des3ident : aesident));
        // userdatafile= conf.getProperty(SncSEECode.SEE_E2EE_USERFILE);
        //logger.debug("userdata file name: "+userdatafile);	
        // CS5: userdatafile config read removed -- no userdata/buffer loading needed
        String active_list = conf.getProperty("E2EE_MODULE_LIST");

        if (conn == null && sworld != null) {
            conn = sworld.getConnection();
            //rebuild the connection in case of unpriviledge connection is unavailable
        }

        if (active_list != null && !active_list.trim().equals("")) {
            try {
                int totalmoduleno = sworld.getModules().length;
                activeModuleList = readModuleList(active_list, totalmoduleno);
                logger.debug("User specified Module list: " + active_list);
            } catch (Exception rml) {
                rml.printStackTrace();
                logger.error("Error while reading user specified module list(E2EE_MODULE_LIST), message:" + rml.getMessage());
                return false;
            }
            if (activeModuleList == null) {
                logger.error("Error while reading user specified module list(E2EE_MODULE_LIST), message: Entries are empty or invalid");
                return false;
            }
        }

        licenses = new Hashtable();
        if (seeworldid == null) {
            try {
                if (activeModuleList != null) {
                    //if user specified module list 
                    module_no = activeModuleList.length;
                    modules = new Module[module_no];
                    for (int i = 0; i < module_no; i++)
                        modules[i] = sworld.getModule(activeModuleList[i]);
                } 
                else {
                    logger.debug("User not specified any module, using all modules.");
                    modules = sworld.getModules();
                    module_no = modules.length;
                    activeModuleList = new int[module_no];
                    for (int i = 0; i < module_no; i++)
                        activeModuleList[i] = i + 1;
                }

                seeworldids = new M_KeyID[module_no];
                seeworlds = new SEEWorld[module_no];
                moduleids = activeModuleList;
                int temp_module_id = 0;
                for (int i = 0; i < module_no; i++) {
                    licenses.put(modules[i].getESN(), conf.getProperty("LICENSE_ESN_" + modules[i].getESN()));
                    logger.debug("license of ESN: " + modules[i].getESN() + " is " + conf.getProperty("LICENSE_ESN_" + modules[i].getESN()));
                    temp_module_id = activeModuleList[i];
					//moduleids[i]=temp_module_id;
                    // CS5: Only look up the published world -- container is managed by hsc_codesafe daemon.
                    // No fallback to createAndPublishSEEWorld -- if the container is not running,
                    // that is a deployment issue to resolve with csadmin, not the host's responsibility. whole chunk changed
                    try {
                        SEEWorld seew = new PublishedSEEWorld(sworld.getConnection(), temp_module_id, E2EE_SEE_PUBLISH_NAME);
                        seeworlds[i] = seew;
                        seeworldids[i] = seew.getWorldID();
                        seeworld = seew;
                        logger.info("SEE world published on module #" + temp_module_id + " has been retrieved.");
                    } catch (Exception e) {
                        if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                            e.printStackTrace();
                        logger.error("Retrieve SEE world on module #" + temp_module_id + " failed: " + e.getMessage());
                        logger.error("Ensure the CS5 container '" + E2EE_SEE_PUBLISH_NAME + "' is deployed and running on module #" + temp_module_id + ". Use: csadmin image list / csadmin status");
                        seeworlds[i] = null;
                        seeworldids[i] = null;
                    }
                }

                checkAliveSEEWorld();
                if (seeworldid == null && module_no > 0) {
                    try {
                        seeworldid = getMergeKeyID(seeworldids);
                    } catch (Exception e) {
                        logger.error("Merge SEE world failed:" + e.getMessage());
                        return false;
                    }
                }
                try {
                    activate_seeworlds();
                } catch (Exception e) {
                    seeworldid = null;
                    module_no = 0;
                    logger.error("E2EE SEE module activation failed:" + e.getMessage());
                    return false;
                }

                loadStoreKey();
                loadRSAprivKey();
                printSEEVersions();
            } catch (Exception ce) {
				//if(logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                ce.printStackTrace();
                logger.error("Error occurs during constructing SEE world:" + ce.getMessage());
            	//throw new SncE2EEException (e.getMessage());

            }
        }

        logger.info("No of modules available: " + module_no);
        return SncSEECode.OK;
    }

    private void printSEEVersions() {
        for (int i = 0; i < module_no; i++) {
            try {
                logger.info("SEE firmware version on module#" + moduleids[i] + ": " + getVersion(seeworldids[i]));
            } catch (Exception e) {
                logger.info("SEE firmware version on module#" + moduleids[i] + " is earlier than 0.1.0.0");
            }
        }
    }

    // check whether the given SEE world is available
    private void checkAliveSEEWorld() {
        try {
            int alive_seeworlds = 0;
            for (int i = 0; i < module_no; i++) {
                if (seeworlds[i] != null && sworld.getModule(moduleids[i]).isUsable()) {
                    alive_seeworlds++;
                }
            }
            if (alive_seeworlds < module_no) {
                SEEWorld[] tempseeworlds = new SEEWorld[alive_seeworlds];
                seeworldids = new M_KeyID[alive_seeworlds];
                int[] tempmoduleids = new int[alive_seeworlds];
                Module[] tempmodules = new Module[alive_seeworlds];
                int count = 0;
                for (int i = 0; i < module_no; i++) {
                    if (seeworlds[i] != null && sworld.getModule(moduleids[i]).isUsable()) {
                        tempseeworlds[count] = seeworlds[i];
                        seeworldids[count] = seeworlds[i].getWorldID();
                        tempmoduleids[count] = moduleids[i];
                        tempmodules[count] = modules[i];
                        count++;
                    } else {
                        System.out.println("Module #" + moduleids[i] + " is not available.");
                        logger.error("Error occur at Module #" + moduleids[i] + ", Module #" + moduleids[i] + " is not available.");
                    }
                }
                seeworlds = tempseeworlds;
                module_no = alive_seeworlds;
                moduleids = tempmoduleids;
                modules = tempmodules;
                if (alive_seeworlds > 0) {
                    seeworldid = getMergeKeyID(seeworldids);
                } else
                    seeworldid = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Error occurs during check alive SEE worlds:" + e.getMessage());
        }
    }

    // CS5: resetSEEWorld simplified -- container keeps running in HSM, just clear state and re-lookup.
    // removePublishedSEEWorld and createAndPublishSEEWorld calls removed.
    private synchronized void resetSEEWorld() {
        try {
            if (resetDone == false) {
                destroyKey(seeworldid);
                seeworldid = null;
                storekeyid = null;
                rsaprivkeyid = null;
                resetDone = true;
                initialize(this.confFile, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Reset attempt failed:" + e.getMessage());
        }
    }

    private void destroyKey(M_KeyID kid) {
        if (kid != null) {
            try {
                M_Command cmd = new M_Command();
                M_Cmd_Args_Destroy args = new M_Cmd_Args_Destroy();
                cmd.cmd = M_Cmd.Destroy;
                cmd.args = args;
                args.key = kid;
                M_Reply reply = conn.transact(cmd);
                if (reply.status != M_Status.OK) {
                    throw new StatusNotOK("Error during " + M_Cmd.toString(cmd.cmd) +
                            ", status " + NFUtils.errorString(reply.status, reply.errorinfo));
                }
                logger.info("Key id :" + kid.toString() + " has been destroyed.");
            } catch (Exception e) {
                logger.error("Key destruction: " + kid.toString() + " failed:" + e.getMessage());
            }
        }
    }

    // CS5: removePublishedSEEWorld() removed -- container lifecycle managed by hsc_codesafe daemon.
    // Use: csadmin image undeploy <image> to remove a container.

    // CS5: createAndPublishSEEWorld() removed -- container is pre-deployed via csadmin image deploy.
    // The host never creates SEE worlds in CS5.

    // CS5: publishSEEWorld() removed -- publishing is handled automatically by the CS5 container
    // via SEElib_InitComplete() on the module side.

    // get the merged key id from given keyids
    private M_KeyID getMergeKeyID(M_KeyID[] keyids) throws Exception {
        if (keyids == null) {
            logger.error("Merge SEE world failed: Keyids is null");
            return null;
        }
        if (keyids.length == 1)
            return keyids[0];
        M_Command cmd = new M_Command();
        M_Cmd_Args_MergeKeyIDs args = new M_Cmd_Args_MergeKeyIDs();
        cmd.cmd = M_Cmd.MergeKeyIDs;
        cmd.args = args;
        args.keys = keyids;
        M_Reply reply = conn.transact(cmd);

        if (reply.status != M_Status.OK) {
            throw new StatusNotOK("Error during " + M_Cmd.toString(cmd.cmd) +
                    ", status " + NFUtils.errorString(reply.status, reply.errorinfo));
        }

        M_KeyID ret = ((M_Cmd_Reply_MergeKeyIDs) reply.reply).newkey;
        return ret;
    }

    // get the pre-session code
    public String[] preSession(String otherParams) throws SncE2EEException {

        String[] pres = new String[3];

        try {
            logger.debug("Get Pre-Session");
            String sessionID = generateSession(SncSEECode.SESSION_ID_LEN, null, null);
            String challengeCode = generateChallenge(SncSEECode.CHALLENGE_CODE_LEN, null);
            String pubkey = getPublicKey(null);

            pres[0] = sessionID;
            pres[1] = challengeCode;
            pres[2] = pubkey;

            logger.debug("Pre-Session, Session ID: " + sessionID);
            logger.debug("Pre-Session, Challenge Code: " + challengeCode);
            logger.debug("Pre-Session, Public Key: " + pubkey);

        } catch (SncE2EEException se) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                se.printStackTrace();
            logger.error(se.toString());
            throw se;
        }

        return pres;
    }

    /* Marshall the given byte array */
    private M_ByteBlock marshal_see_job(byte[] input, byte cmd_type) {
        if (input == null)
            return null;

        byte[] job_bytes = new byte[input.length + 1];
        job_bytes[0] = cmd_type;
        System.arraycopy(input, 0, job_bytes, 1, input.length);
        return new M_ByteBlock(job_bytes);
    }

    // activate created see worlds, this is only called once
    private void activate_seeworlds() throws Exception {
        byte[] result;
        for (int i = 0; i < module_no; i++) {
            try {
                result = activate_transact(marshal_see_job(new byte[0], SncSEECode.SEE_E2EE_CHECK_STATUS), seeworldids[i]);
                if (result != null && result.length > 0 && result[0] == SncSEECode.SEE_STATUS_ACTIVATED) {
                    logger.info("Module #" + moduleids[i] + " has been activated.");
                    continue;
                }
                String esn = modules[i].getESN();
                String license = (String) licenses.get(esn);
                logger.info("Module ESN: [" + esn + "] License: [" + license + "]"); 
                if (license != null && license.length() == 20) {
                    result = activate_transact(marshal_see_job(license.trim().getBytes(), SncSEECode.SEE_E2EE_ACTIVATE), seeworldids[i]);
                    if (result != null && result.length > 0 && result[0] == SncSEECode.SEE_STATUS_EVALUATION) {
                        logger.error("##################################################################################");
                        logger.error("Warning Message: Module #" + moduleids[i] + " is activated under evaluation license. End to end secure module stop functional after 100,000 transactions.");
                        logger.error("##################################################################################");
                        see_evaluation_esns += (see_evaluation_esns.equals("") ? "" : ",") + esn;
                        EVALUATION_MODE = true;
                    } else {
                        // seeworlds[i] = null;
                        // logger.error("Invalid license, Module #" + moduleids[i] + " activation failed.");
                        // throw new SncE2EEException("Activation failed on module#" + moduleids[i]);
                        seeworlds[i] = null;
        String resultStr = (result == null) ? "null" :
                           (result.length == 0) ? "empty" :
                           "value=" + result[0];
        logger.error("Invalid license, Module #" + moduleids[i] + 
                     " activation failed. Result: " + resultStr);
        throw new SncE2EEException("Activation failed on module#" + moduleids[i]);
                    }
                } else if (license != null && (license.length() == 40 || license.trim().length() == 256)) {
                    result = activate_transact(marshal_see_job(HexBin.decode(license.getBytes()), SncSEECode.SEE_E2EE_ACTIVATE), seeworldids[i]);
                    if (result != null && result.length > 0 && result[0] == SncSEECode.SEE_STATUS_ACTIVATED)
                        logger.info("Module #" + moduleids[i] + " is activated.");
                    else {
                        seeworlds[i] = null;
                        logger.error("Activation failed on module#" + moduleids[i] + ": result " + ((result != null && result.length == 1) ? (result[0] + "") : " is empty"));
                        throw new SncE2EEException("Activation failed on module#" + moduleids[i]);
                    }
                } else {
                    seeworlds[i] = null;
                    logger.error("License of module#" + moduleids[i] + " is not correct.");
                    throw new SncE2EEException("License of module#" + moduleids[i] + " is not correct.");
                }
            } catch (Exception e) {
                throw new SncE2EEException(e.getMessage());
            }
        }
    }

    // activate the see world
    private byte[] activate_transact(M_ByteBlock input, M_KeyID worldid) throws Exception {
        byte[] ret = null;

        if (worldid == null) {
            logger.error("E2EE SEE is not initialized.");
            throw new SncE2EEException("E2EE SEE is not initialized.");
        }
        if (input.value.length > 4096) {
            logger.error("Input size is too big.");
            throw new SncE2EEException("Input size is too big ");
        }
        try {
            M_Command cmd = new M_Command();
            M_Cmd_Args_SEEJob args = new M_Cmd_Args_SEEJob();
            cmd.cmd = M_Cmd.SEEJob;
            cmd.args = args;
            args.worldid = worldid;
            args.seeargs = input;
            M_Reply reply = conn.transact(cmd);

            // CS5: traceToString() debug block removed -- use csadmin log get for module-side logging

            if (reply == null)
                throw new StatusNotOK("NEW Error during " + M_Cmd.toString(cmd.cmd) + ", reply is null");
            if (reply.status != M_Status.OK) {
                throw new StatusNotOK("NEW Error during " + M_Cmd.toString(cmd.cmd) + ", status " + NFUtils.errorString(reply.status, reply.errorinfo));
            }
            ret = ((M_Cmd_Reply_SEEJob) reply.reply).seereply.value;
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("SEE transaction failed NEW:" + e.getMessage());
        }
        return ret;
    }

    private byte[] see_transact(M_ByteBlock input, M_KeyID worldid) throws Exception {
        byte[] ret = null;

        if (worldid == null) {
            logger.error("E2EE SEE is not initialized.");
            throw new SncE2EEException("E2EE SEE is not initialized.");
        }
        if (input.value.length > 4096) {
            logger.error("Input size is too big.");
            throw new SncE2EEException("Input size is too big ");
        }
        try {
            M_Command cmd = new M_Command();
            M_Cmd_Args_SEEJob args = new M_Cmd_Args_SEEJob();
            cmd.cmd = M_Cmd.SEEJob;
            cmd.args = args;
            args.worldid = worldid;
            args.seeargs = input;
            M_Reply reply = conn.transact(cmd);

            // CS5: traceToString() debug block removed -- use csadmin log get for module-side logging

            if (reply == null)
                throw new StatusNotOK("Error during " + M_Cmd.toString(cmd.cmd) + ", reply is null");
            if (reply.status != M_Status.OK) {
                if (reply.status == M_Status.SEEWorldFailed || reply.status == M_Status.UnknownID || reply.status == M_Status.CrossModule) {
                    resetDone = false;
                }
                throw new StatusNotOK("Error during " + M_Cmd.toString(cmd.cmd) + ", status " + NFUtils.errorString(reply.status, reply.errorinfo));
            }
            ret = ((M_Cmd_Reply_SEEJob) reply.reply).seereply.value;
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("SEE transaction failed NEW:" + e.getMessage());
        }
        return ret;
    }

    /* load key from key id */
    private void loadStoreKey() throws Exception {

        if (storekeyid == null) {
            Key storekey = null;
            String storekey_ident;

            if (usingDES3)
                storekey_ident = des3ident;
            else if (usingAES)
                storekey_ident = aesident;
            else {
                logger.error("Load store failed: No store key is defined. ");
                throw new SncE2EEException("Load store failed: No store key is defined. ");
            }
            storekey = sworld.getKey(store_key_appname, storekey_ident);
            if (storekey != null) {
                if (storekeyhash == null)
                    storekeyhash = storekey.getData().hash.value;
            } else {
                logger.info("Store key of ident :" + storekey_ident + " cannot be found.");
                throw new SncE2EEException("Store key of ident :" + storekey_ident + " cannot be found.");
            }
            String storekeyhashstr = new String(HexBin.encode(storekeyhash));
            if (storekeyhash != null && loadedkeys.get(storekeyhashstr) != null) {
                storekeyid = loadedkeys.get(storekeyhashstr);
                logger.info("Store key of hash :" + storekeyhashstr + " has been retrieved from cache");
            }

            if (storekeyid == null) {
                for (int module = 0; module < module_no; module++) {
                    M_KeyID cur_storekeyid = null;
                    try {
                        cur_storekeyid = storekey.load(modules[module]);
                    } catch (Exception e) {
                        logger.info("Store Key of ident :" + storekey_ident + " cannot be loaded on module #" + moduleids[module]);
                    }

                    if (cur_storekeyid != null) {
                        loadedkeys.put(storekeyhashstr, cur_storekeyid);
                        logger.info("Store key of hash :" + new String(HexBin.encode(storekeyhash)) + " has been has added to cache");

                        if (iskeyloaded(storekey, seeworldids[module])) {
                            logger.info("Store key of ident :" + storekey_ident + " with key hash=[" + new String(HexBin.encode(storekeyhash)) + "] has been loaded on module#" + moduleids[module]);
                            storekeyid = cur_storekeyid;
                        } else {
                            storekeyid = cur_storekeyid;
                            M_Command cmd = new M_Command();
                            cmd.cmd = M_Cmd.GetTicket;
                            M_Cmd_Args_GetTicket args = new M_Cmd_Args_GetTicket();
                            args.obj = cur_storekeyid;
                            args.destspec = new M_TicketDestination_Details_NamedSEEWorld(seeworldids[module]);
                            args.dest = M_TicketDestination.NamedSEEWorld;
                            cmd.args = args;

                            M_Reply reply = conn.transact(cmd);
                            if (reply.status != M_Status.OK) {
                                throw new StatusNotOK("Error during " + M_Cmd.toString(cmd.cmd) +
                                        ", status " + NFUtils.errorString(reply.status, reply.errorinfo));
                            }
                            M_Ticket ticket = ((M_Cmd_Reply_GetTicket) reply.reply).ticket;
                            byte[] job_bytes = byte2hex(storekeyhash);
                            job_bytes = concatByteArrs(job_bytes, MarshallContext.marshall(ticket));

                            byte[] result = null;
                            if (usingDES3)
                                result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_TICKET_DES3), seeworldids[module]);
                            else
                                result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_TICKET_AES), seeworldids[module]);

                            if (result != null && result.length == 1 && result[0] == 1)
                                logger.info("Store key of ident :" + storekey_ident + " with key hash=[" + new String(HexBin.encode(storekeyhash)) + "] is loaded on module#" + moduleids[module]);
                            else
                                logger.info("Load store key of ident :" + rsaprivident + " with key hash=[" + new String(HexBin.encode(transkeyhash)) + "]  module#" + moduleids[module] + " failed: return code " + (result == null ? "null" : (result[0] + "")));
                        }
                    }
                }
            }
        }
    }

    private String getVersion(M_KeyID seewid) throws Exception {
        byte[] result = see_transact(marshal_see_job(new byte[0], SncSEECode.SEE_E2EE_VERSION), seewid);
        return new String(result);
    }

    private boolean iskeyloaded(Key key, M_KeyID seewid) {
        byte[] job_bytes = key.getData().hash.value;
        try {
            byte[] result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_E2EE_CHECK_KEYLOAD), seewid);
            if (result != null && result.length == 1 && result[0] == 1)
                return true;
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Unable to check the load key.");
            return false;
        }
        return false;
    }

    private void loadRSAprivKey() throws Exception {

        if (rsaprivkeyid == null) {
            Key rsapriv = sworld.getKey(trans_key_appname, rsaprivident);
            if (rsapriv == null) {
                logger.error("RSA Key of ident :" + rsaprivident + " cannot be loaded.");
                throw new SncE2EEException("RSA Key of ident :" + rsaprivident + " cannot be loaded.");
            }
            if (rsapriv != null && transkeyhash == null)
                transkeyhash = rsapriv.getData().hash.value;
            String transkeyhashstr = new String(HexBin.encode(transkeyhash));

            if (transkeyhash != null && loadedkeys.get(transkeyhashstr) != null) {
                rsaprivkeyid = loadedkeys.get(transkeyhashstr);
                logger.info("Trans key of hash :" + transkeyhashstr + " has been retrieved from cache");
            }

            if (rsaprivkeyid == null) {
                for (int module = 0; module < module_no && seeworldids[module] != null; module++) {
                    M_KeyID cur_rsaprivkeyid = null;
                    cur_rsaprivkeyid = rsapriv.load(modules[module]);
                    if (cur_rsaprivkeyid != null) {
                        rsaprivkeyid = cur_rsaprivkeyid;
                        loadedkeys.put(transkeyhashstr, rsaprivkeyid);
                        logger.info("Trans key of hash:" + transkeyhashstr + " has been has been added to cache");

                        if (iskeyloaded(rsapriv, seeworldids[module])) {
                            logger.info("Trans key of ident :" + rsaprivident + " with key hash=[" + new String(HexBin.encode(transkeyhash)) + "] has been loaded on module#" + moduleids[module]);
                        } else {
                            M_Command cmd = new M_Command();
                            cmd.cmd = M_Cmd.GetTicket;
                            M_Cmd_Args_GetTicket args = new M_Cmd_Args_GetTicket();
                            args.obj = cur_rsaprivkeyid;
                            args.destspec = new M_TicketDestination_Details_NamedSEEWorld(seeworldids[module]);
                            args.dest = M_TicketDestination.NamedSEEWorld;
                            cmd.args = args;
                            M_Reply reply = conn.transact(cmd);
                            if (reply.status != M_Status.OK) {
                                throw new StatusNotOK("Error during " + M_Cmd.toString(cmd.cmd) +
                                        ", status " + NFUtils.errorString(reply.status, reply.errorinfo));
                            }
                            M_Ticket ticket = ((M_Cmd_Reply_GetTicket) reply.reply).ticket;

                            byte[] job_bytes = byte2hex(transkeyhash);
                            job_bytes = concatByteArrs(job_bytes, MarshallContext.marshall(ticket));

                            byte[] result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_TICKET_RSA), seeworldids[module]);
                            if (result != null && result.length == 1 && result[0] == 1)
                                logger.info("Trans key of ident :" + rsaprivident + " with key hash=[" + new String(HexBin.encode(transkeyhash)) + "] is loaded on module#" + moduleids[module]);
                            else
                                logger.info("Load trans key of ident :" + rsaprivident + " with key hash=[" + new String(HexBin.encode(transkeyhash)) + "]  module#" + moduleids[module] + " failed: return code " + (result == null ? "null" : (result[0] + "")));
                        }
                    }
                }
            }
        }
    }

    /* get the public key */
    public String getPublicKey(String otherParams) throws SncE2EEException {
        if (cachedPublicKeyString != null)
            return cachedPublicKeyString;

        String publicKey = null;
        try {
            Key rsak = sworld.getKey(trans_key_appname, rsapubident);
            if (rsak != null) {
                for (int module = 0; module < module_no; module++) {
                    try {
                        rsapubkeyid = rsak.loadPublic(modules[module]);
                        M_KeyType_Data_RSAPublic pubkey = (M_KeyType_Data_RSAPublic) rsak.exportPublic().data;
                        BigInteger e = pubkey.e.value;
                        BigInteger n = pubkey.n.value;

                        publicKey = new String(HexBin.encode(n.toByteArray())) + ":" + new String(HexBin.encode(e.toByteArray()));
                        rsak.unLoadPublic(modules[module]);
                        if (publicKey != null) {
                            break;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        logger.error("Error occurs in load public key on module#" + (moduleids[module]) + ":" + e.getMessage());
                    }
                }
            } else {
                logger.error("Public key with appname=" + trans_key_appname + " Ident=" + rsapubident + " is not found.");
                throw new SncE2EEException("Public key with appname=" + trans_key_appname + " Ident=" + rsapubident + " is not found.");
            }
        } catch (Exception kse) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                kse.printStackTrace();
            logger.error("getPublicKey exception: " + kse.toString());
            throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, kse.getMessage());
        }
        cachedPublicKeyString = publicKey;
        return publicKey;
    }

    public String generateChallenge(int length, String otherParams) throws SncE2EEException {
        String challenge = null;
        try {
            challenge = new String(HexBin.encode(random(length)));
        } catch (Exception e) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                e.printStackTrace();
            logger.error(e.toString());
            throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, e.getMessage());
        }
        return challenge;
    }

    public String generateSession(int length, String usrID, String otherParams) throws SncE2EEException {
        String session = null;
        try {
            session = new String(HexBin.encode(random(length)));
        } catch (Exception e) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                e.printStackTrace();
            logger.error(e.toString());
            throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, e.getMessage());
        }
        return session;
    }

    public boolean verifyPassword(String ePinForVerifyPwd, String currentSPin, String usrID, String challenge, String otherParams) throws SncE2EEException {
        try {
            checkEvaluation();
            logger.debug("Verify Password, EPIN: " + ePinForVerifyPwd + ", Current SPIN: " + currentSPin + ", User ID: " + usrID + ", Challenge: " + challenge + ", otherParams: " + otherParams);

            if (ePinForVerifyPwd == null || currentSPin == null || usrID == null || challenge == null || ePinForVerifyPwd.trim().equals("") || currentSPin.trim().equals("") || usrID.trim().equals("") || challenge.trim().equals("")
                    || !isHexFormat(ePinForVerifyPwd.trim()) || !isHexFormat(currentSPin.trim()) || !isHexFormat(challenge.trim())) {
                logger.error("Verify Password, Invalid parameter. parameter can't be null, empty or non hex values(except userid)");
                throw new SncE2EEException(SncSEECode.AUTH_FAILURE, "parameter can't be null, empty or non hex values(except userid)");
            }

            usrID = usrID.toLowerCase();

            byte[] hexepin = byte2hex(HexBin.decode(ePinForVerifyPwd.trim().getBytes()));
            byte[] hexchallenge = byte2hex(HexBin.decode(challenge.trim().getBytes()));
            byte[] hexspin = byte2hex(HexBin.decode(currentSPin.trim().getBytes()));
            byte[] hexuserid = byte2hex(usrID.getBytes());

            if (transkeyhash == null)
                loadRSAprivKey();
            byte[] job_bytes = byte2hex(transkeyhash);
            if (storekeyhash == null)
                loadStoreKey();
            job_bytes = concatByteArrs(job_bytes, byte2hex(storekeyhash));
            job_bytes = concatByteArrs(job_bytes, hexepin);
            job_bytes = concatByteArrs(job_bytes, hexspin);
            job_bytes = concatByteArrs(job_bytes, hexuserid);
            job_bytes = concatByteArrs(job_bytes, hexchallenge);

            byte[] verify_result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_E2EE_VERIFY_PASSWORD), seeworldid);

            if (verify_result != null && verify_result.length == 1 && verify_result[0] == SncSEECode.SEE_REPLY_OK) {
                logger.info("Password Verify Succeed, from User: " + usrID);
                return SncSEECode.OK;
            } else {
                logger.info("Password Verify Failed: password does not match, from User: " + usrID);
                if (verify_result != null)
                    logger.info("returned  error code: " + verify_result[0]);
                throw new SncE2EEException(SncSEECode.AUTH_WRONG_PWD, "password does not match");
            }

        } catch (SncE2EEException se) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                se.printStackTrace();
            logger.error("Password Verify Failed: Error code: " + se.getCode() + ", message: " + se.getMessage() + ", from User: " + usrID);
            throw se;
        } catch (Exception e) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                e.printStackTrace();
            logger.error("Password Verify Failed: Error code: " + SncSEECode.SYSTEM_FAILURE + ", message: " + e.getMessage() + ", from User: " + usrID);
            throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, e.toString());
        }
    }

    public String changePassword(String ePinForChangePwd, String currentSPin, String[] sPinHistory, String usrID, String challenge, String otherParams) throws SncE2EEException {

        String newSpin = null;

        try {
            checkEvaluation();
            logger.debug("Change Password ePin: " + ePinForChangePwd + ", Current SPIN: " + currentSPin + ", User ID: " + usrID + ", Challenge: " + challenge + ", otherParams: " + otherParams);
            if (ePinForChangePwd == null || currentSPin == null || usrID == null || challenge == null ||
                    ePinForChangePwd.trim().equals("") || currentSPin.trim().equals("") || challenge.trim().equals("")
                    || !isHexFormat(ePinForChangePwd.trim()) || !isHexFormat(currentSPin.trim()) || !isHexFormat(challenge.trim())) {
                logger.error("Change Password, Parameter is invalid. parameter can't be null, empty or non hex values(except userid)");
                throw new SncE2EEException(SncSEECode.CHANGE_PWD_FAILURE, "parameter can't be null, empty or non hex values(except userid)");
            }

            if (sPinHistory != null && sPinHistory.length > 16) {
                logger.error("Input size is too big. Maximum password history len is 16.");
                throw new SncE2EEException("Input size is too big ");
            }
            usrID = usrID.toLowerCase();
            byte[] hexepin = byte2hex(HexBin.decode(ePinForChangePwd.trim().getBytes()));
            byte[] hexchallenge = byte2hex(HexBin.decode(challenge.trim().getBytes()));
            byte[] hexspin = byte2hex(HexBin.decode(currentSPin.trim().getBytes()));
            byte[] hexuserid = byte2hex(usrID.getBytes());

            if (transkeyhash == null)
                loadRSAprivKey();

            byte[] transkeyhashhex = byte2hex(transkeyhash);
            byte[] job_bytes = new byte[2 + transkeyhashhex.length];
            System.arraycopy(transkeyhashhex, 0, job_bytes, 2, transkeyhashhex.length);

            if (storekeyhash == null)
                loadStoreKey();
            job_bytes = concatByteArrs(job_bytes, byte2hex(storekeyhash));
            job_bytes = concatByteArrs(job_bytes, hexepin);
            job_bytes = concatByteArrs(job_bytes, hexspin);
            job_bytes = concatByteArrs(job_bytes, hexuserid);
            job_bytes = concatByteArrs(job_bytes, hexchallenge);
            int validpinnum = 0;
            if (sPinHistory != null && sPinHistory.length > 0) {
                job_bytes[0] = (byte) sPinHistory.length;
                if (sPinHistory[0] != null)
                    job_bytes[1] = (byte) sPinHistory[0].trim().length();
                int spinlength = 0;
                for (int i = 0; i < sPinHistory.length; i++) {
                    if (sPinHistory[i] != null && !sPinHistory[i].trim().equals("") && isHexFormat(sPinHistory[i].trim())) {
                        if ((spinlength == 0) || (spinlength > 0 && sPinHistory[i].trim().length() == spinlength)) {
                            job_bytes = concatByteArrs(job_bytes, byte2hex(HexBin.decode(sPinHistory[i].trim().getBytes())));
                            validpinnum++;
                        }
                        if ((spinlength > 0 && sPinHistory[i].trim().length() != spinlength)) {
                            logger.info("History Pin:" + sPinHistory[i] + " has different length (expect " + spinlength + ")");
                            throw new SncE2EEException(SncSEECode.CHANGE_PWD_FAILURE, "History Pin:" + sPinHistory[i] + " has different length (Expect " + spinlength + ")");
                        }
                        if (spinlength == 0)
                            spinlength = sPinHistory[i].trim().length();
                    } else {
                        logger.debug("Pin history entry: " + sPinHistory[i] + " is not valid");
                    }
                }
                if (validpinnum != sPinHistory.length) {
                    job_bytes[0] = (byte) validpinnum;
                }
                if (spinlength > 0) {
                    job_bytes[1] = (byte) spinlength;
                }
            } else {
                job_bytes[0] = 0;
                job_bytes[1] = 0;
            }

            byte[] change_result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_E2EE_CHANGE_PASSWORD), seeworldid);

            if (change_result == null || change_result.length == 0) {
                logger.info("Change Password Failed: SEE failure, from User: " + usrID);
                throw new SncE2EEException("See World failed to change password");
            } else if (change_result.length == 1) {
                if (change_result[0] == 4) {
                    logger.info("Change Password Failed:  password does not match, from User: " + usrID);
                    throw new SncE2EEException(SncSEECode.CHANGE_PWD_OLD_WRONG_PWD, " password does not match");
                } else if (change_result[0] == 5) {
                    logger.info("Change Password Failed: password in history list, from User: " + usrID);
                    throw new SncE2EEException(SncSEECode.CHANGE_PWD_NEW_PWD_USED, "password is in history");
                } else if (change_result[0] == 1) {
                    logger.info("Change Password Failed: See world internal error, from User: " + usrID);
                    throw new SncE2EEException(SncSEECode.CHANGE_PWD_FAILURE, "See world internal error");
                }
                throw new SncE2EEException(SncSEECode.CHANGE_PWD_FAILURE, "malformed encrypted pins: return code " + change_result[0]);
            }
            newSpin = new String(HexBin.encode(change_result));

        } catch (SncE2EEException se) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                se.printStackTrace();
            logger.error("Password Change Failed: Error code: " + se.getCode() + ", message: " + se.getMessage() + ", from User: " + usrID);
            throw se;
        } catch (Exception e) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                e.printStackTrace();
            logger.error("Password Change Failed: Error code: " + SncSEECode.SYSTEM_FAILURE + ", message: " + e.getMessage() + ", from User: " + usrID);
            throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, e.getMessage());
        }

        logger.info("Change Password Succeed, from User: " + usrID);
        logger.info("Change Password Succeed, generate a new store pin for user [" + usrID + "], new SPIN: [" + newSpin + "]");

        return newSpin;
    }

    public String encryptPassword(String clearPassword, String usrID, String otherParams) throws SncE2EEException {

        String spin = null;

        try {
            checkEvaluation();
            logger.info("Encrypt Password, user ID: " + usrID);

            if (clearPassword == null || usrID == null || clearPassword.equals("") || usrID.trim().equals("")) {
                logger.error("Encrypt Parameter is invalid. Parameter can't be null or empty.");
                throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, "parameters can't be null or empty");
            }
            usrID = usrID.toLowerCase();

            byte[] hexpin = byte2hex(clearPassword.getBytes());
            byte[] hexuserid = byte2hex(usrID.getBytes());

            if (storekeyhash == null)
                loadStoreKey();
            
            byte[] job_bytes = byte2hex(storekeyhash);
            job_bytes = concatByteArrs(job_bytes, hexpin);
            job_bytes = concatByteArrs(job_bytes, hexuserid);

            byte[] encrypt_result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_E2EE_ENCRYPT_PASSWORD), seeworldid);
            if (encrypt_result == null || encrypt_result.length == 1) {
                logger.error("Password Encryption failed for user: " + usrID + ": return code " + (encrypt_result == null ? "null" : (encrypt_result[0] + "")));
                throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, "Password encryption fail");
            }
            spin = new String(HexBin.encode(encrypt_result));
            logger.info("Encrypt password to generate new Store PIN for user: [" + usrID + "],  (Encrypt Password) SPIN: [" + spin + "]");

        } catch (Exception e) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                e.printStackTrace();
            logger.error(e.toString());
            throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, e.getMessage());
        }
        return spin;
    }

    public String resetPassword(String ePinForResetPwd, String usrID, String challenge, String otherParams) throws SncE2EEException {

        String spin = null;

        try {
            checkEvaluation();
            logger.debug("Reset Password, EPIN: " + ePinForResetPwd + ", User ID: " + usrID + ", Challenge: " + challenge + ", otherParams: " + otherParams);

            if (ePinForResetPwd == null || usrID == null || challenge == null || ePinForResetPwd.trim().equals("") || usrID.trim().equals("") || challenge.trim().equals("")
                    || !isHexFormat(ePinForResetPwd.trim()) || !isHexFormat(challenge.trim())) {
                logger.error("Reset Password, Parameter is invalid. parameter can't be null, empty or non hex values(except userid)");
                throw new SncE2EEException(SncSEECode.AUTH_FAILURE, "parameter can't be null, empty or non hex values(except userid)");
            }

            usrID = usrID.toLowerCase();

            byte[] hexepin = byte2hex(HexBin.decode(ePinForResetPwd.trim().getBytes()));
            byte[] hexchallenge = byte2hex(HexBin.decode(challenge.trim().getBytes()));
            byte[] hexuserid = byte2hex(usrID.getBytes());

            if (transkeyhash == null)
                loadRSAprivKey();

            if (storekeyhash == null)
                loadStoreKey();

            byte[] job_bytes = byte2hex(transkeyhash);
            job_bytes = concatByteArrs(job_bytes, byte2hex(storekeyhash));
            job_bytes = concatByteArrs(job_bytes, hexepin);
            job_bytes = concatByteArrs(job_bytes, hexuserid);
            job_bytes = concatByteArrs(job_bytes, hexchallenge);

            byte[] reset_result = see_transact(marshal_see_job(job_bytes, SncSEECode.SEE_E2EE_RESET_PASSWORD), seeworldid);

            if (reset_result == null || reset_result.length == 1) {
                logger.error("Password reset failed for user: " + usrID + " code : " + (reset_result == null ? "result is null" : (reset_result[0] + "")));
                throw new SncE2EEException(SncSEECode.RESET_PWD_FAILURE, "Password reset fail");
            }

            spin = new String(HexBin.encode(reset_result));
            logger.info("Reset a new password succeed for user: [" + usrID + "]");
            logger.info("Generated a new Store PIN for user: [" + usrID + "],  (Reset Password) SPIN: [" + spin + "]");

        } catch (Exception e) {
            if (logger.getLogLevel().equalsIgnoreCase(SncLogManager.LOG_LEVEL_HIGH))
                e.printStackTrace();
            logger.error(e.toString());
            throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, e.getMessage());
        }
        return spin;
    }

    private static byte[] random(int size) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] plainText = new byte[size];
        random.nextBytes(plainText);
        return plainText;
    }

    private void printArray(String message, byte[] input) {
        System.out.println(message);
        if (input == null) {
            System.out.println("Bytes Array is NULL");
            return;
        }
        for (int i = 0; i < input.length; i++)
            System.out.print(input[i] + ", ");
        System.out.println("\n----------END Bytes-----------");
    }

    /* reformat the hex to send into SEE world */
    private byte[] byte2hex(byte[] bytearray) {
        int len = bytearray.length;
        byte[] hexarray = new byte[len * 2];
        for (int i = 0; i < len; i++) {
            hexarray[2 * i] = (byte) (((bytearray[i] & 0xf0)) >> 4);
            hexarray[2 * i + 1] = (byte) (bytearray[i] & 0x0f);
        }
        return hexarray;
    }

    private void reverse(byte[] arr) {
        byte temp;
        int len = arr.length;
        for (int i = 0; i < len / 2; i++) {
            temp = arr[i];
            arr[i] = arr[len - 1 - i];
            arr[len - 1 - i] = temp;
        }
    }

    private byte[] concatByteArrs(byte[] barr1, byte[] barr2) {
        if (barr1 == null || barr1.length == 0)
            return barr2;
        if (barr2 == null || barr2.length == 0)
            return barr1;

        byte[] ret = new byte[barr1.length + barr2.length + 1];
        System.arraycopy(barr1, 0, ret, 0, barr1.length);
        ret[barr1.length] = SEP;
        System.arraycopy(barr2, 0, ret, barr1.length + 1, barr2.length);
        return ret;
    }

    private static char[] hextable = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', ':'};

    private void printHex(String name, byte[] ptr) {
        int len = ptr.length;
        System.out.print(name + " Hex is : ");
        int i = 0;
        if (ptr[0] == 9) {
            i = 3;
            System.out.print("9XX");
        }
        for (; i < len; i++) {
            System.out.print(hextable[ptr[i]]);
        }
        System.out.println();
    }

    private void checkEvaluation() throws Exception {
        if (EVALUATION_MODE) {
            if (eval_execution_count >= MAX_EVALUATION_COUNT) {
                throw new SncE2EEException(SncSEECode.SYSTEM_FAILURE, "System has reached maximum evaluation count, please purchase license or restart your application to continue trial.");
            } else
                eval_execution_count++;
        }
    }

    private boolean isHexFormat(String arg) {
        String hexChars = "0123456789ABCDEFabcdef";
        if (arg == null)
            return false;
        arg = arg.trim();
        for (int i = 0; i < arg.length(); i++) {
            if (hexChars.indexOf(arg.charAt(i)) < 0)
                return false;
        }
        return true;
    }

    private int[] readModuleList(String mlist, int totalmoduleno) throws Exception {
        int[] ret;
        int count = 0;
        if (mlist == null || mlist.trim().equals(""))
            return null;
        if (mlist.trim().equals("0")) {
            ret = new int[totalmoduleno];
            for (int i = 0; i < totalmoduleno; i++)
                ret[i] = i + 1;
            return ret;
        }

        StringTokenizer stt = new StringTokenizer(mlist, ", ");
        ret = new int[stt.countTokens()];
        while (stt.hasMoreTokens())
            ret[count++] = Integer.parseInt(stt.nextToken());

        for (int i = 0; i < ret.length; i++) {
            if (ret[i] > totalmoduleno || ret[i] <= 0) {
                throw new SncE2EEException("module no:" + ret[i] + " of E2EE_MODULE_LIST is out of range(1-" + totalmoduleno + "). ");
            }
            for (int j = i + 1; j < ret.length; j++) {
                if (ret[j] == ret[i]) {
                    throw new SncE2EEException("module no:" + ret[i] + " of E2EE_MODULE_LIST is a duplicate entry. ");
                }
            }
        }
        return ret;
    }

    public String changePasswordWithComplexityCheck(String ePinForChangePwd,
            String currentSPin, String[] sPinHistory, String usrID,
            String challenge, String policyid, String otherParams)
            throws SncE2EEException {
        throw new SncE2EEException(SncE2EECode.SYSTEM_FAILURE, "Change password function for this cipher Not implemented yet");
    }

    private String formatEPIN(String epin) {
        if (epin.trim().length() % 2 == 0)
            return epin;
        else
            return "0" + epin;
    }

    public String nativeEncryptPassword(String clearPassword, String usrID, String cfgFileName) {
        SncE2EEnCipherSEE e2eeCipher = new SncE2EEnCipherSEE();
        try {
            e2eeCipher.initialize(cfgFileName, null);
            if (logger != null)
                logger.info("Native Encrypt Password (nativeEncryptPassword), user ID: " + usrID);
            return e2eeCipher.encryptPassword(clearPassword, usrID, null);
        } catch (Exception e) {
            e.printStackTrace();
            if (logger != null)
                logger.error("Native Encrypt Password (nativeEncryptPassword), Failed: " + e.getMessage() + ", user ID: " + usrID);
            return null;
        }
    }
}
