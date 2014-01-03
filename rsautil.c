//modify by Angyrfox.su 2014.1.4
//RSA加密解密
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#define OPENSSLKEY "test.key"
#define PUBLICKEY "test_pub.key"
#define BUFFSIZE 1024

char* my_encrypt(char *str,char *path_key);//加密
char* my_decrypt(char *str,char *path_key);//解密
unsigned char* encrypt(char *source);
char* echo(void);
char* decrypt(char *str);
void hexstr2bin(char hex[],unsigned char *hexdata);
unsigned char* bin2hexstr(char *bin,int len);

unsigned char* encrypt(char *source) {
	char *ptr_en;
	unsigned char *ptr_hex;
	ptr_en=my_encrypt(source,PUBLICKEY);
	ptr_hex = bin2hexstr(ptr_en, strlen(ptr_en));
	free(ptr_en);
	return ptr_hex;
}

char* decrypt(char *str) {
	char *ptr_de;
	ptr_de = my_decrypt(str,OPENSSLKEY);
	return ptr_de;
}

char* echo(void) {
	char *c = "hello world\n";
	return c;
}

void hexstr2bin(char hex[],unsigned char *hexdata) {
	int ii;
	int l=strlen(hex);
	if (l%2!=0) return;

	for (ii=0;ii<l;ii+=2)
	{
		char c= hex[ii];
		char d= hex[ii+1];
		char v;

		if ((c>='A') && ( c<='F')) v=(c-'A'+10)*16;
		if ((c>='a') && ( c<='f')) v=(c-'a'+10)*16;
		if ((c>='0') && ( c<='9')) v=(c-'0')*16;

		if ((d>='A') && ( d<='F')) v=v+(d-'A'+10);
		if ((d>='a') && ( d<='f')) v=v+(d-'a'+10);
		if ((d>='0') && ( d<='9')) v=v+(d-'0');

		(* (hexdata+(ii/2))) = v;
	}
	return ;
}

unsigned char* bin2hexstr(char *bin,int len) {
	 char table[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
					'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	unsigned char *hexstr = malloc(len*2+1);
	unsigned char *hexindex = hexstr;
	int i;
	for ( i=0;i<len;i++)
	{
	   int a = (bin[i]>>4)&0x0F;
	   int b = bin[i]     &0x0F;
		(*hexindex)=table[a];
		hexindex++;
		(*hexindex)=table[b];
		hexindex++;
	}
	(*hexindex)=0;
	return hexstr;
}

char *my_encrypt(char *str,char *path_key){
	char *p_en;
	RSA *p_rsa;
	FILE *file;
	int flen,rsa_len;
	if((file=fopen(path_key,"r"))==NULL){
		perror("open key file error");
		return NULL;    
	}   
	if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
	//~ if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   次句不通不过，无论是否将公钥分离源文件
		ERR_print_errors_fp(stdout);
		return NULL;
	}   
	flen=strlen(str);
	rsa_len=RSA_size(p_rsa);
	p_en=(char *)malloc(rsa_len+1);
	memset(p_en,0,rsa_len+1);
	if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
		return NULL;
	}
	RSA_free(p_rsa);
	fclose(file);
	return p_en;
}

char *my_decrypt(char *str,char *path_key){
	char *p_de;
	unsigned char *p_bin;
	RSA *p_rsa;
	FILE *file;
	int rsa_len;
	if((file=fopen(path_key,"r"))==NULL){
		perror("open key file error");
		return NULL;
	}
	if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	rsa_len=RSA_size(p_rsa);
	p_de=(char *)malloc(rsa_len+1);
	p_bin = (unsigned char *)malloc(rsa_len+1);
	memset(p_de,0,rsa_len+1);
	hexstr2bin(str,p_bin);
	if(RSA_private_decrypt(rsa_len,(unsigned char *)p_bin,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
		return NULL;
	}
	RSA_free(p_rsa);
	free(p_bin);
	fclose(file);
	return p_de;
}
