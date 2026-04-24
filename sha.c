#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __SHA__
#include <immintrin.h>
#define USE_SHA_NI 1
#endif

uint32_t	ror(uint32_t x, uint8_t n) {
	return (x >> n) | (x << (32 - n));
}

uint8_t *message_to_blocks(const char *str, uint64_t *size_allocation, uint8_t *blocks)
{
	size_t len = strlen(str);
	uint64_t bit_len = (uint64_t)len * 8;

	*size_allocation = ((len + 9 + 63) / 64) * 64;

	memcpy(blocks, str, len);

	blocks[len] = 0x80;

	memset(blocks + len + 1, 0, *size_allocation - len - 9);

	for (int i = 0; i < 8; i++)
		blocks[*size_allocation - 1 - i] = (uint8_t)(bit_len >> (i * 8));

	return blocks;
}

char	*convert_res(uint32_t h, char *str)
{
	char hexa[16] = "0123456789abcdef";
	for (uint8_t i = 0; i < 8; i++)
	{
		str[7 - i] = hexa[h % 16];
		h >>= 4;
	}
	return str;
}

static const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#ifdef USE_SHA_NI
static void sha256_compress_ni(uint32_t h_tab[8], const uint8_t *chunk)
{
	__m128i state0, state1;
	__m128i msg0, msg1, msg2, msg3;
	__m128i tmp, mask;
	__m128i abef_save, cdgh_save;

	// Shuffle mask to convert from little-endian to big-endian
	mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

	// Load initial state
	// state0 = {e, f, g, h}, state1 = {a, b, c, d}
	tmp    = _mm_loadu_si128((__m128i *)&h_tab[0]); // a, b, c, d
	state1 = _mm_loadu_si128((__m128i *)&h_tab[4]); // e, f, g, h

	tmp    = _mm_shuffle_epi32(tmp, 0xB1);    // cdab
	state1 = _mm_shuffle_epi32(state1, 0x1B); // efgh
	state0 = _mm_alignr_epi8(tmp, state1, 8); // abef
	state1 = _mm_blend_epi16(state1, tmp, 0xF0); // cdgh

	abef_save = state0;
	cdgh_save = state1;

	// Load and byte-swap message words
	msg0 = _mm_loadu_si128((__m128i *)(chunk + 0));
	msg1 = _mm_loadu_si128((__m128i *)(chunk + 16));
	msg2 = _mm_loadu_si128((__m128i *)(chunk + 32));
	msg3 = _mm_loadu_si128((__m128i *)(chunk + 48));

	msg0 = _mm_shuffle_epi8(msg0, mask);
	msg1 = _mm_shuffle_epi8(msg1, mask);
	msg2 = _mm_shuffle_epi8(msg2, mask);
	msg3 = _mm_shuffle_epi8(msg3, mask);

	// Rounds 0-3
	tmp = _mm_add_epi32(msg0, _mm_loadu_si128((__m128i *)&k[0]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

	// Rounds 4-7
	tmp = _mm_add_epi32(msg1, _mm_loadu_si128((__m128i *)&k[4]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg0 = _mm_sha256msg1_epu32(msg0, msg1);

	// Rounds 8-11
	tmp = _mm_add_epi32(msg2, _mm_loadu_si128((__m128i *)&k[8]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg1 = _mm_sha256msg1_epu32(msg1, msg2);

	// Rounds 12-15
	tmp = _mm_add_epi32(msg3, _mm_loadu_si128((__m128i *)&k[12]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
	msg0 = _mm_sha256msg2_epu32(msg0, msg3);
	msg2 = _mm_sha256msg1_epu32(msg2, msg3);

	// Rounds 16-19
	tmp = _mm_add_epi32(msg0, _mm_loadu_si128((__m128i *)&k[16]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
	msg1 = _mm_sha256msg2_epu32(msg1, msg0);
	msg3 = _mm_sha256msg1_epu32(msg3, msg0);

	// Rounds 20-23
	tmp = _mm_add_epi32(msg1, _mm_loadu_si128((__m128i *)&k[20]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
	msg2 = _mm_sha256msg2_epu32(msg2, msg1);
	msg0 = _mm_sha256msg1_epu32(msg0, msg1);

	// Rounds 24-27
	tmp = _mm_add_epi32(msg2, _mm_loadu_si128((__m128i *)&k[24]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
	msg3 = _mm_sha256msg2_epu32(msg3, msg2);
	msg1 = _mm_sha256msg1_epu32(msg1, msg2);

	// Rounds 28-31
	tmp = _mm_add_epi32(msg3, _mm_loadu_si128((__m128i *)&k[28]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
	msg0 = _mm_sha256msg2_epu32(msg0, msg3);
	msg2 = _mm_sha256msg1_epu32(msg2, msg3);

	// Rounds 32-35
	tmp = _mm_add_epi32(msg0, _mm_loadu_si128((__m128i *)&k[32]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
	msg1 = _mm_sha256msg2_epu32(msg1, msg0);
	msg3 = _mm_sha256msg1_epu32(msg3, msg0);

	// Rounds 36-39
	tmp = _mm_add_epi32(msg1, _mm_loadu_si128((__m128i *)&k[36]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
	msg2 = _mm_sha256msg2_epu32(msg2, msg1);
	msg0 = _mm_sha256msg1_epu32(msg0, msg1);

	// Rounds 40-43
	tmp = _mm_add_epi32(msg2, _mm_loadu_si128((__m128i *)&k[40]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
	msg3 = _mm_sha256msg2_epu32(msg3, msg2);
	msg1 = _mm_sha256msg1_epu32(msg1, msg2);

	// Rounds 44-47
	tmp = _mm_add_epi32(msg3, _mm_loadu_si128((__m128i *)&k[44]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
	msg0 = _mm_sha256msg2_epu32(msg0, msg3);
	msg2 = _mm_sha256msg1_epu32(msg2, msg3);

	// Rounds 48-51
	tmp = _mm_add_epi32(msg0, _mm_loadu_si128((__m128i *)&k[48]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
	msg1 = _mm_sha256msg2_epu32(msg1, msg0);
	msg3 = _mm_sha256msg1_epu32(msg3, msg0);

	// Rounds 52-55
	tmp = _mm_add_epi32(msg1, _mm_loadu_si128((__m128i *)&k[52]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
	msg2 = _mm_sha256msg2_epu32(msg2, msg1);

	// Rounds 56-59
	tmp = _mm_add_epi32(msg2, _mm_loadu_si128((__m128i *)&k[56]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
	msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
	msg3 = _mm_sha256msg2_epu32(msg3, msg2);

	// Rounds 60-63
	tmp = _mm_add_epi32(msg3, _mm_loadu_si128((__m128i *)&k[60]));
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
	tmp = _mm_unpackhi_epi64(tmp, tmp);
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

	// Add back saved state
	state0 = _mm_add_epi32(state0, abef_save);
	state1 = _mm_add_epi32(state1, cdgh_save);

	// Unscramble and store back into h_tab
	tmp    = _mm_shuffle_epi32(state0, 0x1B); // feba
	state1 = _mm_shuffle_epi32(state1, 0xB1); // dchg
	state0 = _mm_blend_epi16(tmp, state1, 0xF0); // dcba
	state1 = _mm_alignr_epi8(state1, tmp, 8);    // hgfe

	_mm_storeu_si128((__m128i *)&h_tab[0], state0); // a, b, c, d
	_mm_storeu_si128((__m128i *)&h_tab[4], state1); // e, f, g, h
}
#endif

char *sha_256(const char *data, char *hash, uint8_t *blocks)
{
	uint32_t h_tab[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	uint64_t size;
	uint8_t *bits = message_to_blocks(data, &size, blocks);

	for (uint8_t sub_c = 0; sub_c < (uint8_t)(size / 64); sub_c++)
	{
		uint8_t *chunk = (bits + (sub_c * 64));

#ifdef USE_SHA_NI
		sha256_compress_ni(h_tab, chunk);
#else
		uint32_t w[64];
		for (int i = 0; i < 16; i++) {
			w[i] = __builtin_bswap32(*(uint32_t *)(chunk + i * 4));
		}
		for (int i = 16; i < 64; i++) {
			uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
			uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint32_t a = h_tab[0];
		uint32_t b = h_tab[1];
		uint32_t c = h_tab[2];
		uint32_t d = h_tab[3];
		uint32_t e = h_tab[4];
		uint32_t f = h_tab[5];
		uint32_t g = h_tab[6];
		uint32_t h = h_tab[7];

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
		h_tab[0] += a;
		h_tab[1] += b;
		h_tab[2] += c;
		h_tab[3] += d;
		h_tab[4] += e;
		h_tab[5] += f;
		h_tab[6] += g;
		h_tab[7] += h;
#endif
	}

	convert_res(h_tab[0], hash);
	convert_res(h_tab[1], hash + 8);
	convert_res(h_tab[2], hash + 16);
	convert_res(h_tab[3], hash + 24);
	convert_res(h_tab[4], hash + 32);
	convert_res(h_tab[5], hash + 40);
	convert_res(h_tab[6], hash + 48);
	convert_res(h_tab[7], hash + 56);
	return (hash);
}

char *atoi_base(unsigned int n, char *tmp)
{
	char *base = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int base_size = strlen(base);
	int i = 64;

	tmp[--i] = '\0';
	if (n == 0) {
		tmp[--i] = base[0];
	} else {
		while (n > 0) {
			tmp[--i] = base[n % base_size];
			n /= base_size;
		}
	}
	return (tmp + i);
}

int main(void)
{
	char *hash = calloc(64, 1);
	char *str = malloc(sizeof(char) * 64);
	char *tmp;
	uint8_t *blocks = calloc(512, 1);

	// time on 42 mac
	// 10e6 = 10_000_000 ≃ 2.9s
	for (unsigned int i = 0; i < 10e6; i++) {
		tmp = atoi_base(i, str);
		hash = sha_256(tmp, hash, blocks);
	}
	printf("word:%s|hash:%s", tmp, hash);
	free(hash);
	free(blocks);
	free(str);
	return (0);
}