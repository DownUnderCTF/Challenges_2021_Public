#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/tcp.h>

#define KEY_LENGTH 16
#define USER_BUFFER 56
#define N 256
static unsigned char *canary;

void flag(int sock){
  char buf[1024];
  FILE *f = fopen("flag.txt", "r");
  fgets(buf, 1024, f);
  write(sock, buf, strlen(buf));
}

void swap(unsigned char *a, unsigned char *b) {
  *a ^= *b;
  *b ^= *a;
  *a ^= *b;
}

void init_RC4_key(unsigned char *S, unsigned char *key){
  int i = 0, j = 0;

  for (i = 0; i < N; i++) {
    S[i] = i;
  }

  for (i = 0; i < N; i++){
    j = (j + S[i] + *(key + i % KEY_LENGTH)) % N;
    swap(&S[i], &S[j]);
  }
}

void RC4_encrypt(unsigned char *S, unsigned char *plaintext, unsigned char *ciphertext){
  int i = 0, j = 0, k = 0, n = 0;

  for (k = 0; k < KEY_LENGTH; k++){
    i = (i + 1) % N;
    j = (j + S[i]) % N;
    swap(&S[i], &S[j]);
    n = S[(S[i] + S[j]) % N];
    *(ciphertext + k) = *(plaintext + k) ^ n;
  }
}

unsigned char* get_random(){
  FILE *fptr = fopen("/dev/urandom","r");
  unsigned char *random = malloc(KEY_LENGTH);
  fread(random, sizeof(char), KEY_LENGTH, fptr);
  fclose(fptr);
  return random;
}

void update_canary(unsigned char *S, unsigned char* buffer){
  unsigned char *plaintext = calloc(KEY_LENGTH, sizeof(unsigned char));
  unsigned char *ciphertext = calloc(KEY_LENGTH, sizeof(unsigned char));

  RC4_encrypt(S, plaintext, ciphertext);

  memcpy(canary, ciphertext, KEY_LENGTH);
  memcpy(&buffer[32], ciphertext, KEY_LENGTH);

  free(plaintext);
  free(ciphertext);
  plaintext = NULL;
  ciphertext = NULL;
}

int check_canary(unsigned char* buffer){
  for (int i = 0; i < KEY_LENGTH; i++){
    if (buffer[32 + i] != canary[i]){
      return 0;
    }
  }
  return 1;  
}

int check_flag(unsigned char* buffer){
  return buffer[48] == '2' && buffer[49] == '4' 
    && buffer[50] == '7' && buffer[51] == 'D' 
    && buffer[52] == 'U' && buffer[53] == 'C' 
    && buffer[54] == 'T' && buffer[55] == 'F';
}

void user_read(int sock, unsigned char *S, unsigned char* buffer){
  memset(buffer, 0, USER_BUFFER);
  update_canary(S, buffer);
  recv(sock, buffer, USER_BUFFER, 0);
}

void challenge_mine(int sock) {
  canary = calloc(KEY_LENGTH, sizeof(unsigned char));
  unsigned char *key = get_random();
  unsigned char *buffer = calloc(USER_BUFFER, sizeof(unsigned char));
  unsigned char S[N];

  init_RC4_key(S, key);

  char banner[] = "Can you defeat the canary and pull the flag from the mine?\n> ";
  char canary1[] = "   ___     ___     ___\n";
  char canary2[] = "  (o o)   (o o)   (o o)\n";
  char canary3[] = " (  V  ) (  V  ) (  V  )\n";
  char canary4[] = "/--m-m- /--m-m- /--m-m-\n";
  char canary5[] = "[chirp] No flag for you!\n> ";

  write(sock, banner, strlen(banner));
  while (1) {
    user_read(sock, S, buffer);
    if (check_canary(buffer) && check_flag(buffer)){
      flag(sock);
      exit(0);
    } else {
      write(sock, canary1, strlen(canary1));
      write(sock, canary2, strlen(canary2));
      write(sock, canary3, strlen(canary3));
      write(sock, canary4, strlen(canary4));
      write(sock, canary5, strlen(canary5));
    }
  }
  
  free(buffer);
  free(key);
  free(canary);
}

int main(int argc, char *argv[]){
  int sockfd, newsockfd, portno, pid;
  socklen_t clilen;
  struct sockaddr_in serv_addr, cli_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  bzero((char *)&serv_addr, sizeof(serv_addr));
  portno = 1337;

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);

  bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  listen(sockfd, 100);
  clilen = sizeof(cli_addr);

  while (1){
    newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    pid = fork();
    if (pid == 0) {
      close(sockfd);
      challenge_mine(newsockfd);
      close(newsockfd);
      exit(0);
    }
    else {
      close(newsockfd);
    }
  }
}
