#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint32_t	ror(uint32_t x, uint8_t n) {
	return (x >> n) | (x << (32 - n));
}

uint8_t	*message_to_blocks(const char *str, uint64_t *size_allocation)
{
	size_t		len = strlen(str);
	uint64_t	L = len * 8;

	*size_allocation = (((L + 1 + 64) + 511) / 512) * 64;
	// * 64 bc normaly, 512 then / 8, in my case, do that in only one operation

	uint8_t *bitset = calloc(*size_allocation, 1);
	if (!bitset) return NULL;

	for (size_t i = 0; i < len; i++) {
		uint8_t c = (uint8_t)str[i];
		bitset[i] = c;
	}
	bitset[L / 8] |= 1 << (7 - (L % 8)); // set the bit after the data to 1

	for (int i = 0; i < 8; i++) {
		*(bitset + *size_allocation - 1 - i) = L;
		L >>= 8; // or L /= 256
	}
	return (bitset);
}

int	main(int argc, char **argv)
{
	uint32_t h0 = 0x6a09e667;
	uint32_t h1 = 0xbb67ae85;
	uint32_t h2 = 0x3c6ef372;
	uint32_t h3 = 0xa54ff53a;
	uint32_t h4 = 0x510e527f;
	uint32_t h5 = 0x9b05688c;
	uint32_t h6 = 0x1f83d9ab;
	uint32_t h7 = 0x5be0cd19;

	uint32_t	k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	
	char *str = "";
	uint64_t size;
	uint8_t *bits = message_to_blocks(str, &size);

	for (int sub_c = 0; sub_c < (size / 64); sub_c++)
	{
		uint8_t *chunk = (bits + (sub_c * 64));
		uint32_t w[64];
		for (int i = 0; i < 16; i++) {
			w[i]  = chunk[(i * 4)];
			w[i] <<= 8;
			w[i] += chunk[(i * 4) + 1];
			w[i] <<= 8;
			w[i] += chunk[(i * 4) + 2];
			w[i] <<= 8;
			w[i] += chunk[(i * 4) + 3];
		}
		for (int i = 16; i < 64; i++) {
			uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
			uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;
		uint32_t f = h5;
		uint32_t g = h6;
		uint32_t h = h7;

		for (int i = 0; i < 64; i++) {
			uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
			uint32_t ch = (e & f) ^ ((~e) & g);
			uint32_t temp1 = h + S1 + ch + k[i] + w[i];
			uint32_t S0 = (ror(a, 2) ^ (ror(a, 13)) ^ (ror(a, 22)));
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		h5 = h5 + f;
		h6 = h6 + g;
		h7 = h7 + h;
	}
	printf("0x%08x%08x%08x%08x%08x%08x%08x%08x\n", h0, h1, h2, h3, h4, h5, h6, h7);
	free(bits);
}
