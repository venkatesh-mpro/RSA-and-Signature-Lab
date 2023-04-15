#include "util.c"
#include "rsa.c"

int main () 
{
	//Task 1 - Deriving a private key

	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();

	// Assign the value of p
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");

	// Assign the value of q
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");

	// Assign the value of e
	BN_hex2bn(&e, "0D88C3");

	BIGNUM* priv_key1 = get_rsa_priv_key(p, q, e);
	printBN("The private key for task1 : ", priv_key1);
	printf("\n");

	//Task 2 - Encrypting a message

	// Assign the empty bignum variables for enc & dec
	BIGNUM* enc = BN_new();
	BIGNUM* dec = BN_new();

	// Assign the private key
	BIGNUM* priv_key = BN_new();
	BN_hex2bn(&priv_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign the public key
	BIGNUM* pub_key = BN_new();
	BN_hex2bn(&pub_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	// Assign the value of mod
	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");

	// Assign the hex of the message (A top secret!)
	BIGNUM* message = BN_new();
	BN_hex2bn(&message, "4120746f702073656372657421");

	printBN("The plaintext message for task2 : ", message);
	enc = rsa_encrypt(message, mod, pub_key);
	printBN("The encrypted message for task2 : ", enc);
	dec = rsa_decrypt(enc, priv_key, pub_key);
	printf("The decrypted message for task2 : ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	//Task 3 - Decrypting a message

	// Assign the value of ciphertext
	BIGNUM* task3_enc = BN_new();
	BN_hex2bn(&task3_enc, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

	// public and private keys are used from task2
	dec = rsa_decrypt(task3_enc, priv_key, pub_key);
	printf("The decrypted message for task3 : ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	//Task 4 - Signing a message

	// Assign the hex value of the message
	BIGNUM* BN_task4 = BN_new();
	BN_hex2bn(&BN_task4, "49206f776520796f75203030302e");

	enc = rsa_encrypt(BN_task4, priv_key, pub_key);
	printBN("The signature for task4 : ", enc);

	dec = rsa_decrypt(enc, mod, pub_key);
	printf("The message for task4 : ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	//Task 5 - Verifying a signature

	//Assign the values
	BIGNUM* BN_task5 = BN_new();
	BIGNUM* S = BN_new();
	BN_hex2bn(&BN_task5, "4c61756e63682061206d6973736c652e");
	BN_hex2bn(&pub_key, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

	dec = rsa_decrypt(S, mod, pub_key);
	printf("The message for task5 : ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	// Changing the signature from 2F to 3F and verifying
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

	dec = rsa_decrypt(S, mod, pub_key);
	printf("The message for task5 : ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	//Task 6 - Manually Verifying an X.509 Certificate

	// Assign the public key
	BIGNUM* task6_pub_key = BN_new();
	BN_hex2bn(&task6_pub_key, "B5BAAAE423E96E90E4679756BDDF7FF4F18E004C2625B29C98EEF686037882C8CFB59F5F1143FF42D9A0C83E42F0119D11E6C76BFB8D44AA7AC91482E8A5A5258E77EF66F5A4A5CCFA3D8780AB1CE84D35DEB61CB05F30C05D1598C46DE423A9AFA1549B57861935F0E1394FA55D99D8737270CEC9BF1C443973870D1B72736E433AAFC3787091B89D10660E028DFFC0FC50023D845B6CBA447ABF9DDE975028CCE47B777BF79A4BD4B6D850B8E325581766C98C1EAEF3C22E8262AAFD7AE402B717A97187275EABF6829B7EF0AAA91B05CB5BAC96B72D33F331C7E42698B5B5C8922D30E50068C7B012978D6724CDF68B49C4C49889253F8D5749162CEB3513");
	printBN("The public key for task6 : ", task6_pub_key);

	// Assign the modulus
	BIGNUM* task6_mod = BN_new();
	BN_hex2bn(&task6_mod, "10001");

	// Assign the signature of the extracted certificate
	BIGNUM* BN_task6 = BN_new();
	BN_hex2bn(&BN_task6, "7f23a7affb02a4045a0b72847f0f8bd9f108e77e3083107582c2d84f123480674722b36a6dd4d8abc14feb816af42af156b8ebf88fae0aeb1a7d947b8b3a431a8f5b8a9a5f3e4006fcddb00ed88cc77296c2b6dfe34191f9ca53e7f0fa6128fc26834e69b9ea5e0c7fd402cefdfac3938eb0e6c3db5df34afed087ac69c431efec56d28fe11ae6f9b052f09f8b0a99b2e79b0a496a7c189ea76e41ab159fc19688db5743147eeeb732cd8afbaf2efcb9b8b69e23468390ddfd91aeb13262fdbdbe99151a870c3efa96ac7013551b80ebeddad64324fabbbb7f0d2a4c15abe58eede6e7c9c343b3f4bdb1d33e363390fa17fcdc55e85dbd9d72d8b6049ffd6247");

	BIGNUM* task6_dec = rsa_decrypt(BN_task6, task6_mod, task6_pub_key);

	printBN("The hash for task6 : ", task6_dec);
	printf("\n");

	printf("The pre-computed hash for task6 : ");
	printf("d8aad516fdcb32f7cc0a8c284ae51e3b25d4fa409b3d470bc873b5c4ec831843");
	printf("\n");

}
