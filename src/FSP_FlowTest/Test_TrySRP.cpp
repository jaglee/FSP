#include "stdafx.h"

//SRP-6
//	I: identity /U
//	P: password	/w
//	s: salt		/S
//	v: verifier	// v = g^x, x = H(s, I, P)	/W
//
//	a, b are generated randomly
//	Client				Server
//		I		->	(lookup s, v)		// identity I, salt s; verifier v
//	x = H(s, I, P)		<-	(s)	
//	A = g^a			->	B = 3v + g^b	// RESTful: A together with I
//						u = H(A, B)
//	u = H(A, B)		<-(B, u)
//	S = (B - 3g^x)^(a + ux)				//== (g^b)^(a+ux) = g^b^a * g^b^(ux) = g^a * g^(ux))^b = (g^a*(g^x)^u)^b
//	M1 = H(A, B, S)		->
//						S = (Av^u)^b
//						verify M1
//	verify M2		<-	M2 = H(A, M1, S)
//	K = H(S)			K = H(S)
void TrySRP6()
{
	const unsigned int BITS_COUNT = 1536;
	const char *U = "FSP_FlowTest";
	const char *S = "FSP_Srv";
	const char *password = "Passw0rd";
	//
	mpz_t p;
	mpz_t g;
	mpz_t t;
	DebugBreak();	// And to single-step, watch without printf_s
	mpz_init_set_str(p, "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
		"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
		"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
		"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
		"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
		"C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
		"83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
		"670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
		, 16);
	mpz_init_set_ui(g, 2);
	mpz_init(t);

	//	Client				Server
	//		I		->	(lookup s, v)	// identity I, salt s; verifier v
	//	x = H(s, I, P)		<-	(s)	
	mpz_class x;
	mpz_class v;

	uint8_t input[1024];
	uint8_t h[64];

	strcpy_s((char *)input, 1024, S);
	strcpy_s((char *)input + strlen(S), 1024 - 80, U);
	strcpy_s((char *)input + strlen(S) + strlen(U), 1024 - 160, password);
	CryptoNaClHash(h, input, strlen(S) + strlen(U) + strlen(password));
	mpz_import(x.get_mpz_t(), strlen(S) + strlen(U) + strlen(password), 1, 1, 0, 0, h);
	// x %= mpz_class(p);	// the value of the 512 bit hash result is clearly less than p
	mpz_powm(v.get_mpz_t(), g, x.get_mpz_t(), p);

	mpz_class a, b;
	// prepare the random generator
	gmp_randstate_t randomState;
	gmp_randinit_default(randomState);
	gmp_randseed_ui(randomState, (unsigned long)time(NULL));

	mpz_urandomb(a.get_mpz_t(), randomState, BITS_COUNT);
	mpz_urandomb(b.get_mpz_t(), randomState, BITS_COUNT);

	//	A = g^a			->	B = 3v + g^b	// RESTful: A together with I
	mpz_class A, B, u;
	mpz_class S1;	// S of server
	mpz_class S_c;	// S of client

	mpz_powm(A.get_mpz_t(), g, a.get_mpz_t(), p);
	mpz_powm(B.get_mpz_t(), g, b.get_mpz_t(), p);
	B += 3*v;

	size_t n, m;
	mpz_export(input, &n, 1, 1, 0, 0, A.get_mpz_t());
	mpz_export(input + n, &m, 1, 1, 0, 0, B.get_mpz_t());
	CryptoNaClHash(h, input, n + m);
	mpz_import(u.get_mpz_t(), n + m, 1, 1, 0, 0, input);

	// u = H(A, B)		<-(B)
	// S = (B - 3g^x)^(a + ux)		// (g^b)^(a+ux) = g^b^a * g^b^(ux) = g^a * g^(ux))^b = (g^a*(g^x)^u)^b
	mpz_class tmp = a + u * x;
	mpz_powm(t, g, x.get_mpz_t(), p);
	S_c = B - 3 * mpz_class(t);
	mpz_powm(t, S_c.get_mpz_t(), tmp.get_mpz_t(), p);
	S_c = mpz_class(t);
	//
	//	M1 = H(A, B, S)	-> (if M1 was lost, no need to calculate u, S and verify M1)
	//					u = H(A, B)
	//					S = (Av^u)^b
	mpz_powm(S1.get_mpz_t(), v.get_mpz_t(), u.get_mpz_t(), p);
	mpz_mul(t, A.get_mpz_t(), S1.get_mpz_t());
	mpz_powm(S1.get_mpz_t(), t, b.get_mpz_t(), p);

	assert(S_c == S1);	// if they are equal, M1, M2 would certainly be equal
	//					verify M1
	//	verify M2		<-	M2 = H(A, M1, S)
	//	K = H(S)			K = H(S)

	mpz_clears(p, g, t, NULL);
}
