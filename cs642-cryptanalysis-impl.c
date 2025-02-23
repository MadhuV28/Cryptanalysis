////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.c
//  Description    : This is the development program for the cs642 first project
//  that
//                   performs cryptanalysis on ciphertext of different ciphers.
//                   See associated documentation for more information.
//
//   Author        : *** MADHU VUYYURU ***
//   Last Modified : *** DATE ***
//

// Include Files
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

// Project Include Files
#include "cs642-cryptanalysis-support.h"

//
// Functions
//**CHECK MEM LEAKS*** */

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentInit
// Description  : This is a function that is called before any cryptanalysis
//                occurs. Use it if you need to initialize some datastructures
//                you may be reusing across ciphers.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentInit(void) {

  // ADD CODE HERE IF NEEDED

  // Return successfully
  return (0);


}

////////////////////////////////////////////////////////////////////////////////
//
// after running cs642Decrypt we call count_words on the decrypted text to have a total count of the words from the givne key
//we will use this count to compare with other key counts and we would like to set the best_key to the key with the highest word count
//we are going to assume that the key that produces the most words is the correct key
//used for ROTX & AFFINE BUT DIFFERENT PROCESS FOR VIGENERE & SUBSTITUTIOn

int count_valid_words_with_dictionary(char *decrypted_text){
  int valid_words=0;
  int dictionary_size= cs642GetDictSize();
  //tokenization using spacing to seperate 'words'
  char *token=strtok(decrypted_text," ");
  while(token != NULL){
    for(int i=0;i<dictionary_size;i++){
      DictWord dict_word=cs642GetWordfromDict(i);
      if(strcasecmp(token,dict_word.word)==0){
        valid_words++;//found a valid word so increment count
        break;
      }
    }
    token=strtok(NULL," ");
  }
  return valid_words;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformROTXCryptanalysis
// Description  : This is the function to cryptanalyze the ROT X cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformROTXCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, uint8_t *key) {
  // ADD CODE HERE
  //this uses brute-force,checks all 25 keys and return key with highest word count
  //TA: BRUTE FORCE IS BEST FOR ROTX AND AFFINE,
  if(ciphertext==NULL || plaintext==NULL || clen !=plen || clen<=0){
    return -1;
  }
  //have decrypted text have +1 lenfor null terminating character to show end of string
  char decrypted_text[plen+1];
  int max_valid_words=0;//current max valid words after dict check
  uint8_t best_key_accurate=0;//store key that results in most vlaid words
  int res;// hold the result of the decryption attempt

  //try all possible keys  
  for(uint8_t k=1;k<=25;k++){
    res=cs642Decrypt(CIPHER_ROTX,(char*)&k,1,decrypted_text,plen,ciphertext,clen);
    //not successful cs642Decrypt
    if(res!=0){
      continue;
    }
    decrypted_text[clen]='\0';
    //extra copy of the decrypted text bc decrypted_text is altered in strncpy
    char temp_decrypted[plen+1];
    strncpy(temp_decrypted,decrypted_text,plen+1);
    int valid_words=count_valid_words_with_dictionary(temp_decrypted);//word count of current key
    //check if current keys count of valid words is greater than current max
    if(valid_words>max_valid_words){
      max_valid_words=valid_words;//if current is > max, set max to current
      best_key_accurate=k;//set best_key_acc to current k becuase that key holds mroe words from dict
      strncpy(plaintext,decrypted_text,plen+1);
    }
  }
  if(max_valid_words>0){
    *key=best_key_accurate;//best key set 
    return 1;
  }
  else{
    return -1;
  }
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformAFFICryptanalysis
// Description  : This is the function to cryptanalyze the Affine cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformAFFICryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, uint8_t *key) {
  // ADD CODE HERE
  //this uses brute-force,checks all possible b keys with all possible a pairs
  //a has  limited number of possibilities, is this the weakness of affine and if so is there really anyone who uses it?
  // polyalpabetic cipher on thursday!!!! MAKE SURE YOU UNDERSTAND IC AND CHI SQUARED FOR VIGENERE
  if(ciphertext==NULL || plaintext==NULL || clen !=plen || clen<=0){
    return -1;
  }
  //coprime values w 26
  int valid_values_a[]={1,3,5,7,9,11,15,17,19,21,23,25};
  int number_valid_a= sizeof(valid_values_a)/sizeof(valid_values_a[0]);

  //have decrypted text have +1 lenfor null terminating character to show end of string
  char decrypted_text[plen+1];
  int max_valid_words=0;//current max valid words after dict check
  uint8_t best_key_pair_accurate[2]={0};//store array of a,b key that results in most vlaid words
  //try all  a vals
  for(int i=0;i<number_valid_a;i++){
    int a = valid_values_a[i];
    //check a vals with all b pairings
    for(uint8_t b =0;b<26;b++){
      uint8_t current_key_pair[2]={a,b};
      int res=cs642Decrypt(CIPHER_AFFI,(char*)&current_key_pair,1,decrypted_text,plen,ciphertext,clen);
      if(res!=0){
        continue;
      }
    decrypted_text[clen]='\0';
    //extra copy of the decrypted text bc decrypted_text is altered in strncpy
    char temp_decrypted[plen+1];
    strncpy(temp_decrypted,decrypted_text,plen+1);
    int valid_words=count_valid_words_with_dictionary(temp_decrypted);//hold word count of current key
    if(valid_words>max_valid_words){
      max_valid_words=valid_words;
      best_key_pair_accurate[0]=a;
      best_key_pair_accurate[1]=b;
      strncpy(plaintext,decrypted_text,plen+1);
    }
  }
}
  if(max_valid_words>0){
    key[0]=best_key_pair_accurate[0];
    key[1]=best_key_pair_accurate[1];
    return 1;
  }
  else{
    return -1;
  }
}

////////////////////////////////////////////////////////////////////////////////
//
//calculate english letter frequency based on given dictionary.  
// use for vigenere & substitution

void calculate_english_frequency(double *english_frequency){
  int total_letters=0;//count total umber of letters
  int counts[26]={0};//a-z freq
  int dict_size=cs642GetDictSize();
  //loop thru each word in dict
  for(int i=0;i<dict_size;i++){
    DictWord word =cs642GetWordfromDict(i);
    char *w=word.word;
    //loop thru each char in word
    for(int j=0;w[j]!='\0';j++){
      if(isalpha(w[j])){
        counts[toupper(w[j])-'A']++;
        total_letters++;
      }
    }
  }
  //clac freq of letters
  for(int i=0;i<26;i++){
    english_frequency[i]=(counts[i]/(double)total_letters*100.0);
  }
}

////////////////////////////////////////////////////////////////////////////////
//calculate index of coincidence for sequence of text
//help to determine key elngth by comp to english,split ciphertext into sequences off length 
//close to .06, get key length, use another freq analysis to index chunks 
//frequency of each letter seen in english text,if IC uniformly distrubted it will be .04 but if close to english, around .06
//get segmeents and check for frequency of letter at each index
//store positions and compute chi squared with english text and compare with frequencys i computed and check if similar

double calculate_Index_Coincidence(char * sequence,int length){
  int counts[26]={0};
  //count freq of letter in sequence
  for(int i=0;i<length;i++){
    if(isalpha(sequence[i])){
      counts[sequence[i]-'A']++;
    }
  }
  double IC=0.0;
  int total_pairs=length*(length-1);
  //IC calc
  for(int i=0;i<26;i++){
    IC+=counts[i]*(counts[i]-1);
  }
  return IC/total_pairs;
}

////////////////////////////////////////////////////////////////////////////////
//split ciphertext given key length and store given length and number of segments

void split_segments(char *ciphertext,int clen, int key_length,char sequences[11][clen]){
  //ciphertext to segments given key length
  for(int i=0;i<key_length;i++){
    int index=0;
    for(int j=i;j<clen;j+=key_length){
      if(isalpha(ciphertext[j])){
        sequences[i][index++]=ciphertext[j];
      }
    }
    sequences[i][index]='\0';
  }
}

////////////////////////////////////////////////////////////////////////////////
//chi squared computation given sequence 
//THURSDAY LECTURE?!:check similarity bet3ween 2 distributions,small chi-squared is good
//add up all and get average chi_squared,which key length has lowest chi_squared value,just want length of key
//if done correctly, lowest chi_squared is correct!  if we knwo its right, dont check all.
//loop thru each index and a-z letters and get chi_squared from decrytped text and try all at specific position to see what gets lowest chi squared 
//should be 26*6

double calculate_chi_squared(char * sequence,int length,int shift, double *english_frequency){
  int count[26]={0};
  //clac freq of letter in sequence
  for(int i=0;i<length;i++){
    if(isalpha(sequence[i])){
      count[(sequence[i]-'A'-shift+26)%26]++;
    }
  }
  double chi_squared=0.0;
  for(int i=0;i<26;i++){
    double expected=english_frequency[i]*length/100.0;
    chi_squared+=pow(count[i]-expected,2)/expected;
  }
  return chi_squared;
}

int find_best_shift(char *sequence,int length,double *english_frequency){
  //find best shift
  double min_chi_square=INFINITY;
  int best_shift=0;
  for(int shift=0;shift<26;shift++){
    double chi_square=calculate_chi_squared(sequence,length,shift,english_frequency);
    if(chi_square<min_chi_square){
      min_chi_square=chi_square;
      best_shift=shift;
    }
  }
  return best_shift;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformVIGECryptanalysis
// Description  : This is the function to cryptanalyze the Vigenere cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformVIGECryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {

  // ADD CODE HERE
  //index coincidence
  //http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/
  //try: find key length first using IC, key length with value ?0.06? is best
  //after find best key length,CHI SQUARED FOR freq analysis
  if(ciphertext==NULL || plaintext==NULL || clen !=plen || clen<=0){
    printf("Invalid input params\n");
    return -1;
  }
  double english_frequency[26];
  calculate_english_frequency(english_frequency);
  int min_key_length=6;
  int max_key_length=11;
  double best_IC=0.0;
  int best_key_length=min_key_length;
  char segment[11][clen];
  //loop thru key lengths
  for(int key_length=min_key_length;key_length<=max_key_length;key_length++){
    //split ciphertext into key_length parts
    split_segments(ciphertext,clen,key_length,segment);
    double total_IC=0.0;
    //calc chi-square by segment
    for(int i=0;i<=key_length-1;i++){
      total_IC+=calculate_Index_Coincidence(segment[i],strlen(segment[i]));
    }
    double average_IC=total_IC/key_length;
    //update best key length calc if current chi is less 
    if(average_IC>best_IC){
      best_IC=average_IC;
      best_key_length=key_length;
    }
  }
  split_segments(ciphertext,clen,best_key_length,segment);
  for(int i=0;i<best_key_length;i++){
    int best_shift=find_best_shift(segment[i],strlen(segment[i]),english_frequency);
    key[i]='A'+best_shift;
  }
    key[best_key_length]='\0';
    int key_index=0;
    for(int i=0;i<clen;i++){
      if(isalpha(ciphertext[i])){
        int shift=key[i%best_key_length]-'A';
        plaintext[i]=((ciphertext[i]-'A'-shift+26)%26)+'A';
        key_index++;
      }
      else{
        plaintext[i]=ciphertext[i];
      }
    }
    plaintext[clen]='\0';
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformSUBSCryptanalysis
// Description  : This is the function to cryptanalyze the substitution cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformSUBSCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {

  // ADD CODE HERE
  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentCleanUp
// Description  : This is a clean up function called at the end of the
//                cryptanalysis of the different ciphers. Use it if you need to
//                release memory you allocated in cs642StudentInit() for
//                instance.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentCleanUp(void) {

  // ADD CODE HERE IF NEEDED
  // Return successfully
  return (0);
}
