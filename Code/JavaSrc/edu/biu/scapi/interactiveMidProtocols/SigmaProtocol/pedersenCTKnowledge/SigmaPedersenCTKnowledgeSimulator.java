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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.pedersenCTKnowledge;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaGroupElementMsg;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaSimulatorOutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;

/**
 * Concrete implementation of Sigma Simulator.
 * This implementation simulates the case that the prover convince a verifier that that the value committed to in the commitment (h, c) is x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaPedersenCTKnowledgeSimulator implements SigmaSimulator{
	/*	
	  This class computes the following calculations:
		  	SAMPLE random values u, v in Zq  
			COMPUTE a = h^u*g^v*c^(-e) (where �e here means �e mod q)
			OUTPUT (a,e,(u,v))
	*/

	private DlogGroup dlog; 		//Underlying DlogGroup.
	private int t;					//Soundness parameter.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaPedersenCTKnowledgeSimulator(DlogGroup dlog, int t, SecureRandom random) {
		
		// Sets the given parameters.
		setParameters(dlog, t, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaPedersenCTKnowledgeSimulator() {
		try {
			//Create Miracl Koblitz 233 Elliptic curve and set default parameters.
			setParameters(new MiraclDlogECF2m("K-233"), 80, new SecureRandom());
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			setParameters(new CryptoPpDlogZpSafePrime(), 80, new SecureRandom());
		}
	}

	/**
	 * If soundness parameter is valid, sets the parameters. Else, throw IllegalArgumentException.
	 * @param dlog
	 * @param t soundness parameter in BITS
	 * @param random
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	private void setParameters(DlogGroup dlog, int t, SecureRandom random) {
		
		//Sets the parameters.
		this.dlog = dlog;
		this.t = t;
		
		//Check the soundness validity.
		if (!checkSoundness()){
			throw new IllegalArgumentException("soundness parameter t does not satisfy 2^t<q");
		}
		
		this.random = random;
	}
	
	/**
	 * Checks the validity of the given soundness parameter.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundness(){
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
	public int getSoundness(){
		return t;
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaPedersenCTKnowledgeInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCTKnowledgeInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput input, byte[] challenge) throws CheatAttemptException{
		//  SAMPLE random values u, v in Zq  
		//	COMPUTE a = h^u*g^v*c^(-e) (where �e here means �e mod q)
		//	OUTPUT (a,e,(u,v))
		//
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		if (!(input instanceof SigmaPedersenCTKnowledgeInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaPedersenCTKnowledgeInput");
		}
		SigmaPedersenCTKnowledgeInput pedersenInput = (SigmaPedersenCTKnowledgeInput) input;
		
		//SAMPLE a random u, v <- Zq
		BigInteger qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		BigInteger u = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger v = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//COMPUTE a = h^u*g^v*c^(-e) (where �e here means �e mod q)
		//Compute h^u
		GroupElement hToU = dlog.exponentiate(pedersenInput.getH(), u);
		//Compute g^v
		GroupElement gToV = dlog.exponentiate(dlog.getGenerator(), v);
		//Compute c^(-e) 
		BigInteger e = new BigInteger(1, challenge);
		BigInteger minusE = dlog.getOrder().subtract(e);
		GroupElement c = dlog.reconstructElement(true, pedersenInput.getCommitment().getC());
		GroupElement cToE = dlog.exponentiate(c, minusE);
		GroupElement a = dlog.multiplyGroupElements(hToU, gToV);
		a = dlog.multiplyGroupElements(a, cToE);
		
		//OUTPUT (a,e,z).
		SigmaGroupElementMsg first = new SigmaGroupElementMsg(a.generateSendableData());
		SigmaPedersenCTKnowledgeMsg second = new SigmaPedersenCTKnowledgeMsg(u,v);
		return new SigmaPedersenCTKnowledgeSimulatorOutput(first, challenge, second);
				
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaPedersenCTKnowledgeInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCTKnowledgeInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput input){
		//Create a new byte array of size t/8, to get the required byte size.
		byte[] e = new byte[t/8];
		//Fill the byte array with random values.
		random.nextBytes(e);
		//Call the other simulate function with the given input and the sampled e.
		try {
			return simulate(input, e);
		} catch (CheatAttemptException e1) {
			//will not occur since the challenge length is valid.
		}
		return null;
	}
	
	/**
	 * Checks if the given challenge length is equal to the soundness parameter.
	 * @return true if the challenge length is t; false, otherwise. 
	 */
	private boolean checkChallengeLength(byte[] challenge){
		//If the challenge's length is equal to t, return true. else, return false.
		return (challenge.length == (t/8) ? true : false);
	}

}
