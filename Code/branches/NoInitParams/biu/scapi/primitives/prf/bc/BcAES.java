package edu.biu.scapi.primitives.prf.bc;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.AESEngine;

import edu.biu.scapi.primitives.prf.AES;

/**
 * Concrete class of prf family for AES. This class wraps the implementation of Bouncy castle.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public final class BcAES extends BcPRP implements AES{

	/**
	 * Passes the AESEngine of BC to the abstract super class
	 */
	public BcAES() {
		super(new AESEngine());
		
	}

	/**
	 * initializes this AES with secret key.
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//AES key size should be 128/192/256 bits long
		if(len!=16 && len!=24 && len!=32){
			throw new InvalidKeyException("AES key size should be 128/192/256 bits long");
		}
		super.init(secretKey);
	}
	
	/**
	 * initializes this AES with secret key and auxiliary parameters.
	 * @param secretKey the secret key
	 * @param params algorithm parameters
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//AES key size should be 128/192/256 bits long
		if(len!=16 && len!=24 && len!=32){
			throw new InvalidKeyException("AES key size should be 128/192/256 bits long");
		}
		super.init(secretKey, params);
	}
}