/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: testing code for cryptographic functions based on FourQ 
************************************************************************************/   

#include "../FourQ_api.h"
#include "../FourQ_params.h"
 
#include "test_extras.h"
#include <stdio.h>
#include "aes.h"
#include "blake2.h"


// Benchmark and test parameters  
#if defined(GENERIC_IMPLEMENTATION)
    #define BENCH_LOOPS       1000      // Number of iterations per bench
    #define TEST_LOOPS        1000       // Number of iterations per test
    #define SEL_K             18
    #define SEL_T             1024
#else 
    #define BENCH_LOOPS       1000
    #define TEST_LOOPS        1000
    #define SEL_K             18
    #define SEL_T             1024
#endif
//ECCRYPTO as defined in FourQ.h is a enum to handle error codes
void print_hex(unsigned char* arr, int len)
{
    int i;
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
}
 


int main()
{
    
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    
//AES variables  
    unsigned char sk_aes[32] = {0x54, 0xa2, 0xf8, 0x03, 0x1d, 0x18, 0xac, 0x77, 0xd2, 0x53, 0x92, 0xf2, 0x80, 0xb4, 0xb1, 0x2f, 0xac, 0xf1, 0x29, 0x3f, 0x3a, 0xe6, 0x77, 0x7d, 0x74, 0x15, 0x67, 0x91, 0x99, 0x53, 0x69, 0xc5}; 
    block key;
	key = toBlock((uint8_t*)sk_aes);
	setKey(key);
    block* prf_out;
    unsigned char * prf_out2;
	prf_out = malloc(16*2);
	prf_out2 = malloc(16*2);
    uint64_t ii ,i,index;
	ii = 1;
	i = 0;
    
    
// Variables for key pairs and  BPV 

    unsigned char secret_key[32] =  {0x54, 0xa2, 0xf8, 0x03, 0x1d, 0x18, 0xac, 0x77, 0xd2, 0x53, 0x92, 0xf2, 0x80, 0xb4, 0xb1, 0x2f, 0xac, 0xf1, 0x29, 0x3f, 0x3a, 0xe6, 0x77, 0x7d, 0x74, 0x15, 0x67, 0x91, 0x99, 0x53, 0x69, 0xc5}; 

    unsigned char* publicAll_Y;
    publicAll_Y = malloc(SEL_T*64);
    unsigned char* publicAll_R, *secret_all;
    publicAll_R = malloc(SEL_T*64);
    secret_all = malloc(SEL_T*32);

    unsigned char publicTemp[64];
    unsigned char publicTempVer[64];


// Messages and hash values 
    
    uint8_t message[32] = {0};
    uint8_t message1[32] = {1};
    unsigned char * h;
    h = malloc(32);
    unsigned char * h_check;
    h_check = malloc(32);
    unsigned char * concatMsg;
    concatMsg = malloc(64);
    unsigned char hashedMsg[64] = {0}; 
    
//  Benchmarking variables 
    unsigned char R_hashed[32];
    double SignTime, VerifyTime;
    SignTime = 0.0;
    VerifyTime = 0.0;
    clock_t flagSignStart, flagVerStart;
	clock_t flagSignEnd, flagVerEnd; 
    unsigned long long cycles, cycles1, cycles2;     
    unsigned long long vcycles, vcycles1, vcycles2;

    vcycles = 0;
    cycles = 0;
//  Other variables 
    point_t sig;
    bool verify = true;
 
    // ......................... KeyGen .............................
    for (i=0;i<SEL_T;i++){ // To generate the y_i and Y[i]= y_i x G  and publish Y[i] as the public key
        ecbEncCounterMode(i,2,prf_out);
        memmove(prf_out2,prf_out,32);

        modulo_order((digit_t*)prf_out2, (digit_t*)prf_out2);
        // blake2b(prf_out2, &i, NULL, 32, 8, 0);
        // printf("in KEygen  for index %d = ",i );
        // print_hex(prf_out2,32);
        // printf("\n");

        Status = PublicKeyGeneration(prf_out2, publicTemp);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        // printf("in KEygen  for index %d = ",i );
        // print_hex(publicTemp,64);
        // printf("\n");

        memmove(publicAll_Y+i*64, publicTemp, 64);

        
    }
 

    for (i=0;i <SEL_T;i++){ // To generate r_i and R[i]= r_i x G  and publish R[i] as a part of the secret key

        ecbEncCounterMode(i,2,prf_out);
        memmove(prf_out2,prf_out,32);
        modulo_order((digit_t*)prf_out2, (digit_t*)prf_out2);
        // blake2b(prf_out2, &i, NULL, 32, 8, 0);
        // printf("in KEygen  for index %d = ",i );
        // print_hex(prf_out2,32);
        // printf("\n");

        



        Status = PublicKeyGeneration(prf_out2, publicTemp);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        memmove(secret_all+i*32, prf_out2, 32);
        memmove(publicAll_R+i*64, publicTemp, 64);
        
    }


  // ............................ Sign ..................................
    int zz;
 
    point_extproj_t TempExtproj;
    point_extproj_precomp_t TempExtprojPre;
    point_extproj_t R_sign;
    unsigned char secretTemp[32];
    unsigned char secretTemp2[32];
    unsigned char lastSecret[32];
    unsigned char lastPublic[64];
    digit_t* r = (digit_t*)(lastSecret);    

    unsigned char secretKeyTemp[32];
    unsigned char secretKeyTemp2[32];
    unsigned char sigma[32];
    digit_t* x_i = (digit_t*)(sigma); 
    point_extproj_t Y_vfy;
    unsigned char lastPublicVer[64];
    unsigned char verPoint[64];
    point_extproj_t TempExtprojVer;
    point_extproj_precomp_t TempExtprojPreVer;


   //\\\\  Check VARS 

    unsigned char myChecks[64];


    for (zz = 0; zz < BENCH_LOOPS; ++zz) {
        flagSignStart = clock();
        cycles1 = cpucycles(); 
        // The following code is separated from the for loop mainly to initilize the values of r_temp and r to be used in the a add_mod_order() func

        blake2b(hashedMsg, message, secret_key, 64,32,32); // hash the message with secret key to get the indexes for r_i

        index = hashedMsg[0] + ((hashedMsg[1]/64) * 256);
    
        ecbEncCounterMode(index,2,prf_out);
        memmove(secretTemp,prf_out,32);

        modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);

        // blake2b(secretTemp, &index, NULL, 32, 8, 0);
        // memmove(secretTemp,scalar_table +32*index,32);
        memmove(publicTemp,publicAll_R +64*index,64);
        point_setup((point_affine*)publicTemp, R_sign);

        // if (ecc_point_validate(R_sign))
			// printf("The point is set Sign R_sign -- 1\n");

        index = hashedMsg[2] + ((hashedMsg[3]/64) * 256);
        ecbEncCounterMode(index,2,prf_out);
        memmove(secretTemp2,prf_out,32);

        modulo_order((digit_t*)secretTemp2, (digit_t*)secretTemp2);

        // blake2b(secretTemp2, &index, NULL, 32, 8, 0);
        // memmove(secretTemp2,scalar_table +32*index,32);
        memmove(publicTemp,publicAll_R +64*index,64);
        point_setup((point_affine*)publicTemp, TempExtproj);

        R1_to_R2(TempExtproj, TempExtprojPre);
        
        add_mod_order((digit_t*)secretTemp, (digit_t*)secretTemp2, r);
        eccadd(TempExtprojPre,R_sign);

 


   

        for (i = 2; i < SEL_K; ++i) { // Same as above happens in the loop
            index = hashedMsg[2*i] + ((hashedMsg[2*i+1]/64) * 256);
          
            ecbEncCounterMode(index,2,prf_out);
            memmove(secretTemp,prf_out,32);

            modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);
            
            // printf("in KEygen  for index %d = ",index );
            // print_hex(secretTemp,32);
            // printf("\n");

            memmove(publicTemp,publicAll_R +64*index,64);
            point_setup((point_affine*)publicTemp, TempExtproj);

            R1_to_R2(TempExtproj, TempExtprojPre);

            eccadd(TempExtprojPre,R_sign);   // Add the R[i]'s and compute the final R

            add_mod_order((digit_t*)secretTemp, r, r); // Add the r_i's and compute the final r
        }

        eccnorm(R_sign, (point_affine*)lastPublic);

        // printf("lastPublic = ");
        // print_hex(lastPublic,64);
        // printf("\n");

        // modulo_order((digit_t*)lastSecret, (digit_t*)lastSecret);

        // ecc_mul_fixed((digit_t*)lastSecret, (point_affine*)publicTemp);
        // Status = PublicKeyGeneration(lastSecret, publicTemp);
        // if (Status != ECCRYPTO_SUCCESS) {
        //     goto cleanup;
        // }

        // printf("publicTemp = ");
        // print_hex(publicTemp,64);
        // printf("\n");

        // // // BPVOnline(lastSecret, lastPublic);
        // // // printf("After BPVOnline Function\n");

        // printf("lastPublic = ");
        // print_hex(lastPublic,64);
        // printf("\n");

          // modulo_order(r, r);

        // ecc_mul_fixed((digit_t*)lastSecret, (point_affine*)publicTemp);

        // printf("publicTemp = ");
        // print_hex(publicTemp,64);
        // printf("\n");
// =========================================== Second part of Sign
 
        blake2b(h, lastPublic, NULL, 32,64,0); 
        memmove(concatMsg, message,32); // Concatenate h and m
        memmove(concatMsg+32, h, 32);
        blake2b(hashedMsg, concatMsg, NULL, 64,64,0); // Hash m||h

        index = hashedMsg[0] + ((hashedMsg[1]/64) * 256);
    
        ecbEncCounterMode(index,2,prf_out);
        memmove(secretKeyTemp,prf_out,32);

        modulo_order((digit_t*)secretKeyTemp, (digit_t*)secretKeyTemp);


        index = hashedMsg[2] + ((hashedMsg[3]/64) * 256);

        ecbEncCounterMode(index,2,prf_out);
        memmove(secretKeyTemp2,prf_out,32);

        modulo_order((digit_t*)secretKeyTemp2, (digit_t*)secretKeyTemp2);
        
        
        add_mod_order((digit_t*)secretKeyTemp, (digit_t*)secretKeyTemp2, x_i);


        for (i = 2; i < SEL_K; ++i) { // Same as above happens in the loop

            index = hashedMsg[2*i] + ((hashedMsg[2*i+1]/64) * 256);
          
            ecbEncCounterMode(index,2,prf_out);
            memmove(secretKeyTemp,prf_out,32);
            modulo_order((digit_t*)secretKeyTemp, (digit_t*)secretKeyTemp);

 

            

            // blake2b(secretTemp, &index, NULL, 32, 8, 0);
            // memmove(secretTemp,scalar_table +32*index,32);

            // ecc_mul_fixed((digit_t*)secretKeyTemp, (point_affine*)myChecks);
            // printf("in sign for index %d = ", index);
            // print_hex(myChecks,64);
            // printf("\n");
            add_mod_order((digit_t*)secretKeyTemp, (digit_t*)(sigma), (digit_t*)(sigma)); // Add the x_i's and compute the final x_i

        }
        
        //ecc_mul_fixed(x_i, (point_affine*)myChecks);

        // printf("in sign1 = ");
        // print_hex(myChecks,64);
        // printf("\n");
        //modulo_order((digit_t*)sigma, (digit_t*)sigma);

        subtract_mod_order((digit_t*)(lastSecret),(digit_t*)(sigma) ,(digit_t*)(sigma)); 
        //modulo_order(x_i, x_i);
        flagSignEnd = clock();
        SignTime = SignTime +(double)(flagSignEnd-flagSignStart);


// =========================================== The End of second part of sign

//            point_setup(R_sign, R_point);  // Convert the final R to unsigned char * to be hashed into h
//            encode(R_point, R_char); 
//            blake2b(h, R_char, NULL, 32,32,0); 
//            strcpy(concatMsg, message); // Concatenate h and m
//            memcpy(concatMsg+32, h, 32);
//            blake2b(hashedMsg, concatMsg, NULL, 64,64,0); // Hash m||h
//            index = hashedMsg[0] + ((hashedMsg[0+1]/64) * 256); // Find the indexes for the private keys using a public hash function
//            ecbEncCounterMode(index,2,prf_out); // Regenerate the y_i
//            memmove(prf_out2,prf_out,32);
//            digit_t* y  = (digit_t*)prf_out2;
//            index = hashedMsg[1] + ((hashedMsg[1+1]/64) * 256);
//            ecbEncCounterMode(index,2,prf_out);
//            memmove(prf_out2,prf_out,32);
//            digit_t* y_temp = (digit_t*)prf_out2;
//            add_mod_order(y_temp, y,y);

//            for ( i = 2; i < 18; ++i) { // Same as above happens in the loop
 
//                index = hashedMsg[2*i] + ((hashedMsg[2*i+1]/64) * 256);
//                ecbEncCounterMode(index,2,prf_out);
//                memcpy(prf_out2,prf_out,32);
//                y_temp = (digit_t*)prf_out2; // Add the y_i's and compute the final y
//                add_mod_order(y_temp, y,y);

     
//            }
        


//            subtract_mod_order(r, y,y); // Compute y= r-y and output y as a component of the signature along with h
//            flagSignEnd = clock();
//            SignTime = SignTime +(double)(flagSignEnd-flagSignStart);
            cycles2 = cpucycles(); 
            cycles = cycles + (cycles2 - cycles1);

// // ............................ Verify ..................................


       
        flagVerStart =clock(); 
        vcycles1 = cpucycles();
        blake2b(h, lastPublic, NULL, 32,64,0); 
        memmove(concatMsg, message,32); // Concatenate msg with h 
        memmove(concatMsg+32, h, 32);
        blake2b(hashedMsg, concatMsg, NULL, 64,64,0);

        index = hashedMsg[0] + ((hashedMsg[1]/64) * 256);

        memmove(publicTempVer,publicAll_Y +64*index,64);

        point_setup((point_affine*)publicTempVer, Y_vfy);


        index = hashedMsg[2] + ((hashedMsg[3]/64) * 256);

        memmove(publicTempVer,publicAll_Y +64*index,64);
        point_setup((point_affine*)publicTempVer, TempExtprojVer);

        R1_to_R2(TempExtprojVer, TempExtprojPreVer);
        
        eccadd(TempExtprojPreVer,Y_vfy);

        for (i = 2; i < SEL_K; ++i) { // Same as above happens in the loop





            index = hashedMsg[2*i] + ((hashedMsg[2*i+1]/64) * 256);
            memmove(publicTempVer,publicAll_Y+64*index,64);

            point_setup((point_affine*)publicTempVer, TempExtprojVer);
            R1_to_R2(TempExtprojVer, TempExtprojPreVer);
            eccadd(TempExtprojPreVer,Y_vfy);   // Add the R[i]'s and compute the final R

        }

      //  eccnorm(Y_vfy, (point_affine*)myChecks);

        // printf("in very = ");
        // print_hex(myChecks,64);
        // printf("\n");
        modulo_order(x_i, x_i);
       // ecc_mul_fixed((digit_t*)(sigma), (point_affine*)verPoint);
        Status = PublicKeyGeneration((digit_t*)(sigma), (point_affine*)verPoint);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        point_setup((point_affine*)verPoint, TempExtprojVer);

        R1_to_R2(TempExtprojVer, TempExtprojPreVer);

        eccadd(TempExtprojPreVer,Y_vfy);


        ///=== Check 
         
        eccnorm(Y_vfy, (point_affine*)myChecks);

        // printf("in very    = ");
        // print_hex(myChecks,64);
        // printf("\n");
      //  encode(P, verPoint);  // Convert rG to unsigned char * 
        blake2b(h_check, myChecks, NULL, 32,64,0);  // Hash it to get h_check

        //        printf("in very = ");
        // print_hex(h_check,64);
        // printf("\n");

        for (i = 0; i<32; i++){ // Compare h_check with h

            if (h[i] != h_check[i]){
                    verify = false;
            
            }
        }



//            vcycles1 = cpucycles();
//            flagVerStart =clock();       
//            strcpy(concatMsg, message); // Concatenate msg with h 
//            memcpy(concatMsg+32, h, 32);
//            blake2b(hashedMsg, concatMsg, NULL, 64,64,0); // hash the concatenation to find the index for the public keys
//            for (i = 0; i < 18; ++i) {
//                index = hashedMsg[i] + ((hashedMsg[i+1]/64) * 256);
//                ecbEncCounterMode(index,2,prf_out);
//                eccadd(Y[index],Y_vfy); // Y_vfy = Y_vfy + Y[index] 
//            }
//            ecc_mul_fixed(y, P);  // Given y is a signature component, compute P = yG -> similar to P = sG as in the scheme
//            point_setup(P, P_extproj_t); 
//            R1_to_R2(P_extproj_t, P_final); 
//            eccadd(P_final,Y_vfy);  // Add P and Y_vfy -> (r-y)G - yG = rG
//            point_setup(Y_vfy, P);
//            encode(P, P_char);  // Convert rG to unsigned char * 
//            blake2b(h_check, P_char, NULL, 32,32,0);  // Hash it to get h_check

//            for (i = 0; i<32; i++){ // Compare h_check with h

//                if (h[i] != h_check[i]){
//                    verify = false;
            
//                }
//            }

           flagVerEnd =clock();  
           VerifyTime = VerifyTime + (double)(flagVerEnd-flagVerStart);
           vcycles2 = cpucycles(); 
           vcycles = vcycles + (vcycles2 - vcycles1);
    }     

    if (verify){

        printf("\n\n\n\Signature is VERIFIED\n");
        printf("\nSignature is VERIFIED\n\n\n\n");
    }

    printf("%fus per sign\n", ((double) (SignTime * 1000)) / CLOCKS_PER_SEC / zz * 1000);
    printf("%fus per verification\n", ((double) (VerifyTime * 1000)) / CLOCKS_PER_SEC / zz * 1000);
    printf("Signing runs in ...................................... %2lld ", cycles/zz);print_unit;
    printf("\n");
    printf("Verify runs in ....................................... %2lld ", vcycles/zz);print_unit;
    printf("\n");
    printf("%fus end-to-end delay\n", ((double) ((SignTime+VerifyTime) * 1000)) / CLOCKS_PER_SEC / zz * 1000);

 
    printf("\n\n THIS IS TO SHOW THAT THE FILE COMPILES\n\n\n");




 
    goto cleanup;


cleanup:


    
    free(prf_out);
    free(prf_out2);    
    
    free(publicAll_Y);
    free(publicAll_R);

    free(secret_all);
    free(h);
    free(concatMsg);
    free(h_check);
    return Status;
 
}
