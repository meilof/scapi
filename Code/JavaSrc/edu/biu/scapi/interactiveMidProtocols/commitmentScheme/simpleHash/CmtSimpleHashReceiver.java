/**
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * 
 * Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
 * This file is part of the SCAPI project.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 * We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
 * http://crypto.biu.ac.il/SCAPI.
 * 
 * SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * 
 */
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.simpleHash;

import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRBasicCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * This class implements the receiver side of Simple Hash commitment.
 * 
 * This is a commitment scheme based on hash functions. 
 * It can be viewed as a random-oracle scheme, but its security can also be viewed as a 
 * standard assumption on modern hash functions. Note that computational binding follows 
 * from the standard collision resistance assumption. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtSimpleHashReceiver implements CmtReceiver, SecureCommit {
	
	/*
	 * runs the following protocol:
	 * "Commit phase
	 *		WAIT for a value c
	 *		STORE c
	 *	Decommit phase
	 *		WAIT for (r, x)  from C
	 *		IF NOT
	 *		�	c = H(r,x), AND
	 *		�	x <- {0, 1}^t
	 *		      OUTPUT REJ
	 *		ELSE
	 *		      OUTPUT ACC and value x"	 
	 */
	
	private Map<Long , byte[]> commitmentMap;
	private Channel channel;	
	private CryptographicHash hash;
	private int n; //security parameter.

	/**
	 * Constructor that receives a connected channel (to the receiver), the hash function
	 * agreed upon between them and a security parameter n.
	 * The committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	 * @param channel
	 * @param hash
	 * @param n security parameter
	 * 
	 */
	public CmtSimpleHashReceiver(Channel channel, CryptographicHash hash, int n) {
		this.channel = channel;
		this.hash = hash;
		this.n = n;
		commitmentMap = new Hashtable<Long, byte[]>();
		
		//No pre-process in SimpleHash Commitment
	}

	/**
	 * Run the commit phase of the protocol:
	 * "WAIT for a value c
	 *	STORE c".
	 */
	public CmtRCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		Serializable message = null;
		try{
			message = channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive commitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive commitment. The error is: " + e.getMessage());
		}
		if (!(message instanceof CmtSimpleHashCommitmentMessage)){
			throw new IllegalArgumentException("the received message is not an instance of CTCSimpleHashCommitmentMessage");
		}
		
		CmtSimpleHashCommitmentMessage msg = (CmtSimpleHashCommitmentMessage) message;
		commitmentMap.put(Long.valueOf(msg.getId()), msg.getCommitment());
		return new CmtRBasicCommitPhaseOutput(msg.getId());
	}

	/**
	 * Run the decommit phase of the protocol:
	 * "WAIT for (r, x)  from C
	 *	IF NOT
	 *	�	c = H(r,x), AND
	 *	�	x <- {0, 1}^t
	 *		OUTPUT REJ
	 *	ELSE
	 *	  	OUTPUT ACC and value x".
	 */
	public CmtCommitValue receiveDecommitment(long id) throws ClassNotFoundException, IOException{
		//Receive the message from the committer.
		Serializable message = null;
		try {
			message = channel.receive();

		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive decommitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive decommitment. The error is: " + e.getMessage());
		}
		
		if (!(message instanceof CmtSimpleHashDecommitmentMessage)){
			throw new IllegalArgumentException("the received message is not an instance of CTCSimpleHashDecommitmentMessage");
		}
		CmtSimpleHashDecommitmentMessage msg = (CmtSimpleHashDecommitmentMessage) message;
		
		//Compute c = H(r,x)
		byte[] x = msg.getX();
		byte[] r = msg.getR().getR();
		
		//create an array that will hold the concatenation of r with x
		byte[] cTag = new byte[n + x.length];
		System.arraycopy(r,0, cTag, 0, r.length);
		System.arraycopy(x, 0, cTag, r.length, x.length);
		byte[] hashValArrayTag = new byte[hash.getHashedMsgSize()];
		hash.update(cTag, 0, cTag.length);
		hash.hashFinal(hashValArrayTag, 0);
		
		//Fetch received commitment according to ID
		byte[] receivedCommitment = commitmentMap.get(Long.valueOf(id));
		
		//Checks that c = H(r,x)
		if (Arrays.equals(receivedCommitment, hashValArrayTag))
			return new CmtByteArrayCommitValue(x);
		//In the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
		//For now we return null as a mode of reject. If the returned value of this function is not null then it means ACCEPT
		return null;
	}
	
	/**
	 * No pre-process is performed for Simple Hash Receiver, therefore this function returns null! 
	 */
	@Override
	public Object[] getPreProcessedValues() {
		return null;
	}

	@Override
	public Object getCommitmentPhaseValues(long id) {
		return commitmentMap.get(id);
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The given value must be of type ByteArrayCommitValue");
		return (byte[]) value.getX();
	}
}
