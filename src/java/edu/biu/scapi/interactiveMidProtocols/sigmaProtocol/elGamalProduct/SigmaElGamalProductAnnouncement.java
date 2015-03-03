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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalProduct;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * Concrete implementation SigmaProtocol message. <p>
 * This message contains two GroupElement sendable data and used when the DH prover send the first message to the verifier.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalProductAnnouncement implements SigmaProtocolMsg {

	private static final long serialVersionUID = 1208840175220495797L;
	
	private GroupElementSendableData a1;
	private GroupElementSendableData a2;
	private GroupElementSendableData a3;
	private GroupElementSendableData a4;
	
	public SigmaElGamalProductAnnouncement(GroupElementSendableData a1,
			                                      GroupElementSendableData a2,
			                                      GroupElementSendableData a3,
			                                      GroupElementSendableData a4) {
		this.a1 = a1;
		this.a2 = a2;
		this.a3 = a3;
		this.a4 = a4;
	}
	
	public GroupElementSendableData getA1() { return a1; }
	public GroupElementSendableData getA2() { return a2; }
	public GroupElementSendableData getA3() { return a3; }
	public GroupElementSendableData getA4() { return a4; }
}
