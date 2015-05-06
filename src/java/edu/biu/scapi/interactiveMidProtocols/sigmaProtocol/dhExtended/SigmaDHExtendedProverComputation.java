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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dhExtended;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * Concrete implementation of Sigma Protocol prover computation. <p>
 * 
 * This protocol is used for a prover to convince a verifier that the input tuple (g1,...,gm,h1,...,hm) is an 
 * extended Diffie-Hellman tuple, meaning that there exists a single w in Zq such that hi=gi^w for all i.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.3 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDHExtendedProverComputation implements SigmaProverComputation, DlogBasedSigma{
	
	/*	
	  This class computes the following calculations:
		  	SAMPLE a random r <- Zq and COMPUTE ai = gi^r for all i
			SET a=(a1,...,am)
			COMPUTE z = r + ew mod q.
	*/	
	
	private DlogGroup dlog;						// Underlying DlogGroup.
	private int t; 								// Soundness parameter in BITS.
	protected SecureRandom random;
	private SigmaDHExtendedProverInput input;	// Contains g and h arrays and w. 
	private BigInteger r;						// The value chosen in the protocol.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	public SigmaDHExtendedProverComputation(DlogGroup dlog, int t, SecureRandom random) {
		
		//Sets the parameters.
		this.dlog = dlog;
		this.t = t;
		
		//Check the soundness validity.
		if (!checkSoundnessParam()){
			throw new IllegalArgumentException("soundness parameter t does not satisfy 2^t<q");
		}
		
		this.random = random;
		
	}
	
	/**
	 * Checks the validity of the given soundness parameter.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundnessParam(){
		//If soundness parameter does not satisfy 2^t<q, return false.
		BigInteger soundness = new BigInteger("2").pow(t);
		BigInteger q = dlog.getOrder();
		if (soundness.compareTo(q) >= 0){
			return false;
		}
		return true;
	}

	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return t;
	}

	/**
	 * Computes the first message of the protocol.<p>
	 * "SAMPLE a random r in Zq<p>
	 * COMPUTE ai = gi^r for all i". <p>
	 * @param input MUST be an instance of SigmaDHExtendedProverInput.
	 * @return the computed message
	 * @throws IllegalArgumentException if input is not an instance of SigmaDHExtendedProverInput.
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput input) {
		if (!(input instanceof SigmaDHExtendedProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDHExtendedProverInput");
		}

		SigmaDHExtendedProverInput dhInput = (SigmaDHExtendedProverInput) input;
		SigmaDHExtendedCommonInput params = dhInput.getCommonParams();
		if (params.getGArray().size() != params.getHArray().size()){
			throw new IllegalArgumentException("the given g and h array are not in the same size");
		}
		this.input = dhInput;
		
		//Sample random r in Zq
		BigInteger qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//get g array from the input.
		ArrayList<GroupElement> gArray = params.getGArray();
		ArrayList<GroupElementSendableData> aArray = new ArrayList<GroupElementSendableData>();
		int len = gArray.size();
		
		for (int i=0; i<len; i++){
			//Compute ai = gi^r.
			GroupElement a = dlog.exponentiate(gArray.get(i), r);
			aArray.add(a.generateSendableData());
		}
		
		
		//Create and return SigmaDHExtendedMsg with aArray.
		return new SigmaDHExtendedMsg(aArray);
	}

	/**
	 * Computes the second message of the protocol.<p>
	 * "COMPUTE z = (r + ew) mod q".<p>
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		//Compute z = (r+ew) mod q
		BigInteger q = dlog.getOrder();
		BigInteger e = new BigInteger(1, challenge);
		BigInteger ew = (e.multiply(input.getW())).mod(q);
		BigInteger z = r.add(ew).mod(q);
		
		//Delete the random value r
		r = BigInteger.ZERO;
				
		//Create and return SigmaBIMsg with z.
		return new SigmaBIMsg(z);	
	}
	
	/**
	 * Checks if the given challenge length is equal to the soundness parameter.
	 * @return true if the challenge length is t; false, otherwise. 
	 */
	private boolean checkChallengeLength(byte[] challenge){
		//If the challenge's length is equal to t, return true. else, return false.
		return (challenge.length == (t/8) ? true : false);
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaDHSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaDHExtendedSimulator(dlog, t, random);
	}
}
