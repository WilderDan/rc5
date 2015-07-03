/*
 *  Author:                Dan Wilder
 *
 *  Instructor:            M. W. Schulte
 *  School:                University of Missouri - St. Louis (UMSL)
 *  Class: 	           CS 4780 - System Admin/Network Security   
 *  Semester:              Summer 2015
 *  
 *  Assignment:            Project 1 - RC5 Encryption Implementation
 *  Due Date:              09 Jul 2015 by 23:59 
 *	   
 *  Description: 
 *
 *      This project will implement the RC5 encryption algorithm with
 *    the following parameters: w = 32 bits (4 bytes), r = 12 rounds,
 *    b = 8 bytes for key K. 
 *
 *      The program executable is to be called  rc5. The program will take 
 *    a single command line argument of the key in hex [16 hex characters]. 
 *    The program will read the message as ASCII characters from standard 
 *    input until EOF is detected. 
 * 
 *      Each block will be 8 characters [64 bits] split into two 32-bit pieces,
 *    A and B. Note that it will be "little-endian" so that A is the lower half
 *    of the word. The final block will be extended with bytes of 0 if needed. 
 *    
 *      The output is the be printed to the screen as hexadecimal bytes.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* RC5 works with words; let's emphasize this. Here is 32-bit */
typedef unsigned int WORD;

/* Encryption Parameters */
#define w 32
#define r 12
#define b 8
#define t 26
#define c 2

/* Rotation Operator */
#define ROTATE_L(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))

/* Magic Constants */
WORD P = 0xb7e15163;
WORD Q = 0x9e3779b9;

/* Expanded Key Table */ 
WORD S[t];

/* Prototypes */
void setup(unsigned char *);
void encrypt(unsigned int *, unsigned int *);

/****************************************************************************
 * main
 ****************************************************************************/

int main(int argc, char **argv) {
  
  unsigned char K[b]; 
 
  if (argc < 2) { 
    printf("Key not supplied... Exiting!\n");
    exit(1);
  }
  
  strncpy(K, argv[1], sizeof(K));

  setup(K);

  puts("Working! :)");
  return 0;
}

/****************************************************************************
 * setup
 ****************************************************************************/

void setup(unsigned char *K) {

  WORD C, D, L[c]; /* L will be zeroed */
  int u = w/8;     /* u = number of bytes per word */
  int i, j, h; 
 
  // Copy secret key into L
  for(i = b-1; i >= 0; --i) 
    L[i/u] = (L[i/u] << 8) + K[i];

  // Initialize Array S
  for (S[0] = P, i = 1; i < t; ++i)
    S[i] = S[i-1] + Q;

  // Mix in Secret Key
  for (i=j=h=C=D=0; h < 3*t; ++h, i=(i+1)%t, j=(j+1)%c) {
    C = S[i] = ROTATE_L(S[i] + (C + D), 3);
    D = L[j] = ROTATE_L(L[j] + (C + D), (C+D));
  } 
}

/****************************************************************************
 * encrypt
 ****************************************************************************/

void encrypt(WORD *input, WORD *output) {
 
  WORD A = input[0] + S[0];
  WORD B = input[1] + S[1];

  int i;
  for (i = 1; i <= r; i++) {
    A = ROTATE_L(A^B, B) + S[2*i];
    B = ROTATE_L(B^A, A) + S[2*i+1];
  }

  output[0] = A;
  output[1] = B;
}
