#include "KProbeResistantMatrix.h"

#include <NTL/GF2.h>
#include <NTL/GF2X.h>
#include <NTL/GF2E.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/GF2EX.h>

using namespace NTL;

// private declarations
void calculate_k_resistant_matrix_row(jbyte *, int, int, int);
GF2E int_to_GF2E(int);

JNIEXPORT jobjectArray JNICALL Java_edu_biu_protocols_yao_primitives_KProbeResistantMatrixBuilder_createMatrix
(JNIEnv * env, jobject obj, jint n, jint t, jint K, jint N) {
    int m = N * t;
    
    //Define byte[] class
    jclass byteArrayClass = env->FindClass("[B"); 
    
    // create object array that will hold the matrix rows
    // each row is of size m = N * t, and there are n rows.
    // java: byte[][] matrix = new byte[n][];
    jobjectArray matrix = env->NewObjectArray(n, byteArrayClass, NULL); // matrix is currently holding n objects.

    // initialize the GF2 extension with an irreducible polynomial of size t as modulus.
    // essentially we are creating F_{2^t}
    GF2X gf2e_modulus = BuildIrred_GF2X(t);
    GF2E::init(gf2e_modulus);
    
    // for each row i in {0, ..., n-1}
    for (int i = 0; i < n; i++) {

	// java: java_row[i] = new byte[m];
	jbyteArray java_row_i = env->NewByteArray(m);

	// map the java row to a native row
	jbyte * native_row_i = env->GetByteArrayElements(java_row_i, 0);

	// native_row[i] = calculate_k_resistant_matrix_row(t, K, N);
	calculate_k_resistant_matrix_row(native_row_i, t, K, N);

	// release the native row (and copy back: java_row[i] <- native_row[i])
	env->ReleaseByteArrayElements(java_row_i, native_row_i, 0);
	
	// java: matrix[i] = java_row[i];
	env->SetObjectArrayElement(matrix, i, java_row_i);
    }
    
    return matrix;
}

void calculate_k_resistant_matrix_row(jbyte * matrix_row, int t, int K, int N) {
    GF2EX p = random_GF2EX(K-1); // gets a random polynomial in F_{2^t}[x] of degree K-1
    
    for (int i = 1; i <= N; i++) { // we calculate P(1)_2, ..., P(N)_2
	GF2E i_element = int_to_GF2E(i);

	// v = p(i)
	GF2X v = rep(eval(p, i_element));
	
	// matrix_row[j] = v;
	int first_index = (i - 1) * t;
	for (int j = 0; j < t; j++) {
	    if (IsOne(coeff(v, j))) {
		matrix_row[first_index + j] = 1;
	    } else {
		matrix_row[first_index + j] = 0;
	    }
	}
    }

    // at this point matrix_row is populated
    return;
}

GF2E int_to_GF2E(int num) {
    GF2X num_as_gf2x; // initially zero
    int bits = num;
    int i = 0;

    // for each bit in num, if the bit is 1, turn on the proper coeff in the gf2x polynomial
    while (bits) {
	if (bits & 1) {
	    SetCoeff(num_as_gf2x, i);
	}
	i++;
	bits >>= 1;
    }
    
    return to_GF2E(num_as_gf2x);
}
