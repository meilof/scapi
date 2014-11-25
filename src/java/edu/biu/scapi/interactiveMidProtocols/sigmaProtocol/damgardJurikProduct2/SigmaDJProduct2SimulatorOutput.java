/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2014 - SCAPI (http://crypto.biu.ac.il/scapi)
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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct2;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of SigmaSimulatorOutput, used by SigmaDamgardJurikProduct2Simulator.<p>
 * 
 * It contains the a, e, z types used in the above mentioned concrete simulator.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJProduct2SimulatorOutput implements SigmaSimulatorOutput{
	
	private SigmaDJProduct2FirstMsg a;
	private byte[] e;
	private SigmaDJProduct2SecondMsg z;
	
	/**
	 * Sets the given messages and challenge.
	 * @param a protocol's first message 
	 * @param e protocol's challenge
	 * @param z protocol's second message 
	 */
	public SigmaDJProduct2SimulatorOutput(SigmaDJProduct2FirstMsg a, byte[] e, SigmaDJProduct2SecondMsg z){
		this.a = a;
		this.e = e;
		this.z = z;
	}

	/**
	 * Returns the protocol's first message.
	 * @return protocol's first message.
	 */
	public SigmaDJProduct2FirstMsg getA() {
		return a;
	}

	/**
	 * Returns the protocol's challenge.
	 * @return protocol's challenge.
	 */
	public byte[] getE() {
		return e;
	}

	/**
	 * Returns the protocol's second message.
	 * @return protocol's second message.
	 */
	public SigmaDJProduct2SecondMsg getZ() {
		return z;
	}
}
