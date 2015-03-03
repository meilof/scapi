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
package edu.biu.scapi.circuits.garbledCircuit;

/**
 * This class holds the garbled tables of the justGarbled circuit.<p>
 * In just garbled the garbled tables is held in one dimensional byte array. Thus, when we wish to 
 * relate to it as a double byte array as held in SCAPI, we use a double byte array whose first location
 * holds the one dimensional byte array.  
 * The garbled circuit will hold an instance of this class. <p>
 * This way, when we want to change the garbled tables, we just have to change the pointer of the tables in this class. 
 * 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class JustGarbledGarbledTablesHolder implements GarbledTablesHolder{

	/**
	 * 
	 */
	private static final long serialVersionUID = 6520314182106273536L;
	private byte[] garbledTables;
	
	/**
	 * Sets the given garbled tables.
	 * @param garbledTables
	 */
	public JustGarbledGarbledTablesHolder(byte[] garbledTables){
		this.garbledTables = garbledTables;
	}

	@Override
	public byte[][] toDoubleByteArray(){
		
		byte[][] garbledTablesInZeroLocation = new byte[1][];
		
		garbledTablesInZeroLocation[0] = garbledTables;
		
		
		return garbledTablesInZeroLocation;
	}
	
	/**
	 * Sets the given garbled tables. <P>
	 * This allows changing the circuit inner content with no time.
	 * @param garbledTables of the circuit.
	 */
	public void setGarbledTables(byte[] garbledTables){
		this.garbledTables = garbledTables;
	}
}
