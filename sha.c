#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __SHA__
#include <immintrin.h>
#define USE_SHA_NI 1
#endif

#define CHUNK_SIZE   10000
#define TOTAL        100000000UL
#define BASE_CHARS   "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
// #define BASE_CHARS   "abcdefghijklmnopqrstuvwxyz"
#define BASE_SIZE    (sizeof(BASE_CHARS) - 1)

typedef struct s_work_queue
{
	unsigned long		next;
	unsigned long		total;
	const char			*target_hash;
	volatile unsigned int	found;
	char				match_word[65];
	char				match_hash[65];
}	t_work_queue;

typedef struct s_worker
{
	t_work_queue	*queue;
	uint8_t			blocks[64];
	char			last_word[65];
	char			last_hash[65];
}	t_worker;

uint32_t	ror(uint32_t x, uint8_t n) {
	return (x >> n) | (x << (32 - n));
}

static const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#ifdef USE_SHA_NI
static void sha256_compress_ni(uint32_t h_tab[8], const uint8_t *chunk)
{
	__m128i state0, state1;
	__m128i msg0, msg1, msg2, msg3;
	__m128i tmp, mask;
	__m128i abef_save, cdgh_save;

	mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

	tmp    = _mm_loadu_si128((__m128i *)&h_tab[0]);
	state1 = _mm_loadu_si128((__m128i *)&h_tab[4]);
	tmp    = _mm_shuffle_epi32(tmp, 0xB1);
	state1 = _mm_shuffle_epi32(state1, 0x1B);
	state0 = _mm_alignr_epi8(tmp, state1, 8);
	state1 = _mm_blend_epi16(state1, tmp, 0xF0);
	abef_save = state0;
	cdgh_save = state1;

	msg0 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(chunk +  0)), mask);
	msg1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(chunk + 16)), mask);
	msg2 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(chunk + 32)), mask);
	msg3 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)(chunk + 48)), mask);

#define SHA_ROUND2(m, ki) \
	tmp = _mm_add_epi32(m, _mm_loadu_si128((__m128i *)&k[ki])); \
	state1 = _mm_sha256rnds2_epu32(state1, state0, tmp); \
	tmp = _mm_unpackhi_epi64(tmp, tmp); \
	state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

	SHA_ROUND2(msg0,  0)
	SHA_ROUND2(msg1,  4) msg0 = _mm_sha256msg1_epu32(msg0, msg1);
	SHA_ROUND2(msg2,  8) msg1 = _mm_sha256msg1_epu32(msg1, msg2);
	SHA_ROUND2(msg3, 12)
		msg0 = _mm_sha256msg2_epu32(_mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4)), msg3);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);
	SHA_ROUND2(msg0, 16)
		msg1 = _mm_sha256msg2_epu32(_mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4)), msg0);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);
	SHA_ROUND2(msg1, 20)
		msg2 = _mm_sha256msg2_epu32(_mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4)), msg1);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);
	SHA_ROUND2(msg2, 24)
		msg3 = _mm_sha256msg2_epu32(_mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4)), msg2);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);
	SHA_ROUND2(msg3, 28)
		msg0 = _mm_sha256msg2_epu32(_mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4)), msg3);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);
	SHA_ROUND2(msg0, 32)
		msg1 = _mm_sha256msg2_epu32(_mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4)), msg0);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);
	SHA_ROUND2(msg1, 36)
		msg2 = _mm_sha256msg2_epu32(_mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4)), msg1);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);
	SHA_ROUND2(msg2, 40)
		msg3 = _mm_sha256msg2_epu32(_mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4)), msg2);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);
	SHA_ROUND2(msg3, 44)
		msg0 = _mm_sha256msg2_epu32(_mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4)), msg3);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);
	SHA_ROUND2(msg0, 48)
		msg1 = _mm_sha256msg2_epu32(_mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4)), msg0);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);
	SHA_ROUND2(msg1, 52)
		msg2 = _mm_sha256msg2_epu32(_mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4)), msg1);
	SHA_ROUND2(msg2, 56)
		msg3 = _mm_sha256msg2_epu32(_mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4)), msg2);
	SHA_ROUND2(msg3, 60)

#undef SHA_ROUND2

	state0 = _mm_add_epi32(state0, abef_save);
	state1 = _mm_add_epi32(state1, cdgh_save);

	tmp    = _mm_shuffle_epi32(state0, 0x1B);
	state1 = _mm_shuffle_epi32(state1, 0xB1);
	state0 = _mm_blend_epi16(tmp, state1, 0xF0);
	state1 = _mm_alignr_epi8(state1, tmp, 8);

	_mm_storeu_si128((__m128i *)&h_tab[0], state0);
	_mm_storeu_si128((__m128i *)&h_tab[4], state1);
}
#endif

static inline void	fill_base_word_and_block(unsigned long n, char *word, uint8_t *blocks)
{
	static const char	base[] = BASE_CHARS;
	unsigned int		len;

	memset(blocks, 0, 64);
	if (n == 0)
	{
		word[0] = base[0];
		word[1] = '\0';
		blocks[0] = base[0];
		len = 1;
	}
	else
	{
		len = 0;
		for (unsigned long value = n; value > 0; value /= BASE_SIZE)
			len++;
		word[len] = '\0';
		for (unsigned long value = n, i = len; i > 0; --i)
		{
			char c = base[value % BASE_SIZE];
			word[i - 1] = c;
			blocks[i - 1] = (uint8_t)c;
			value /= BASE_SIZE;
		}
	}
	blocks[len] = 0x80;
	blocks[63] = (uint8_t)(len * 8);
}

static char	*convert_res(uint32_t h, char *str)
{
	static const char	hexa[] = "0123456789abcdef";

	for (uint8_t i = 0; i < 8; i++)
	{
		str[7 - i] = hexa[h & 0x0f];
		h >>= 4;
	}
	return str;
}

char	*sha_256_block(const uint8_t *chunk, char *hash)
{
	uint32_t h_tab[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

#ifdef USE_SHA_NI
	sha256_compress_ni(h_tab, chunk);
#else
	uint32_t w[64];
	for (int i = 0; i < 16; i++)
		w[i] = __builtin_bswap32(*(const uint32_t *)(chunk + i * 4));
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t s1 = ror(w[i- 2],17) ^ ror(w[i- 2], 19) ^ (w[i- 2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	uint32_t a=h_tab[0], b=h_tab[1], c=h_tab[2], d=h_tab[3];
	uint32_t e=h_tab[4], f=h_tab[5], g=h_tab[6], h=h_tab[7];

	for (int i = 0; i < 64; i++) {
		uint32_t S1   = ror(e,6) ^ ror(e,11) ^ ror(e,25);
		uint32_t ch   = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + S1 + ch + k[i] + w[i];
		uint32_t S0   = ror(a,2) ^ ror(a,13) ^ ror(a,22);
		uint32_t maj  = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = S0 + maj;
		h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
	}
	h_tab[0]+=a; h_tab[1]+=b; h_tab[2]+=c; h_tab[3]+=d;
	h_tab[4]+=e; h_tab[5]+=f; h_tab[6]+=g; h_tab[7]+=h;
#endif
	convert_res(h_tab[0], hash);
	convert_res(h_tab[1], hash + 8);
	convert_res(h_tab[2], hash + 16);
	convert_res(h_tab[3], hash + 24);
	convert_res(h_tab[4], hash + 32);
	convert_res(h_tab[5], hash + 40);
	convert_res(h_tab[6], hash + 48);
	convert_res(h_tab[7], hash + 56);
	hash[64] = '\0';
	return hash;
}

void *work(void *data)
{
	t_worker	*w = (t_worker *)data;
	unsigned long	start;
	unsigned long	end;

	while (1)
	{
		if (__atomic_load_n(&w->queue->found, __ATOMIC_RELAXED))
			break;
		start = __atomic_fetch_add(&w->queue->next, CHUNK_SIZE, __ATOMIC_RELAXED);
		if (start >= w->queue->total)
			break;
		end = start + CHUNK_SIZE;
		if (end > w->queue->total)
			end = w->queue->total;

		for (unsigned long i = start; i < end; i++) {
			if (__atomic_load_n(&w->queue->found, __ATOMIC_RELAXED))
				return NULL;
			fill_base_word_and_block(i, w->last_word, w->blocks);
			sha_256_block(w->blocks, w->last_hash);
			if (w->queue->target_hash != NULL
				&& strcmp(w->last_hash, w->queue->target_hash) == 0
				&& __atomic_exchange_n(&w->queue->found, 1, __ATOMIC_RELAXED) == 0)
			{
				strcpy(w->queue->match_word, w->last_word);
				strcpy(w->queue->match_hash, w->last_hash);
				return NULL;
			}
		}
	}
	return NULL;
}

// time on 42 mac
// 10e6 = 10_000_000 ≃ 2.9s

// time on serv-mat
// 10e6 = 10_000_000 ≃ 0.85s

// time on pc-linux-home
// 10e6 = 10_000_000 ≃ 0.55s
 
// time multi-thread pc-linux-home
// 10e7 = 100_000_000 ≃ 0.48s

int main(int argc, char **argv)
{
	int number_of_worker = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (number_of_worker <= 0)
		number_of_worker = 12;

	t_work_queue queue = {
		.next = 0,
		.total = TOTAL,
		.target_hash = NULL,
		.found = 0,
		.match_word = {0},
		.match_hash = {0}
	};

	if (argc > 2)
	{
		fprintf(stderr, "usage: %s [sha256]\n", argv[0]);
		return 1;
	}
	if (argc == 2)
	{
		if (strlen(argv[1]) != 64)
		{
			fprintf(stderr, "sha256 must be 64 hex characters\n");
			return 1;
		}
		queue.target_hash = argv[1];
		queue.total = ULONG_MAX;
	}

	t_worker  *worker_tab = calloc(number_of_worker, sizeof(t_worker));
	pthread_t *threads    = malloc(sizeof(pthread_t) * number_of_worker);

	if (worker_tab == NULL || threads == NULL)
		return 1;

	for (int i = 0; i < number_of_worker; i++)
		worker_tab[i].queue = &queue;

	for (int i = 0; i < number_of_worker; i++)
		pthread_create(&threads[i], NULL, work, worker_tab + i);

	for (int i = 0; i < number_of_worker; i++)
		pthread_join(threads[i], NULL);

	if (queue.target_hash != NULL)
	{
		if (!queue.found && sizeof(unsigned long) == sizeof(uint64_t))
		{
			fill_base_word_and_block(ULONG_MAX, worker_tab[0].last_word, worker_tab[0].blocks);
			sha_256_block(worker_tab[0].blocks, worker_tab[0].last_hash);
			if (strcmp(worker_tab[0].last_hash, queue.target_hash) == 0)
			{
				queue.found = 1;
				strcpy(queue.match_word, worker_tab[0].last_word);
				strcpy(queue.match_hash, worker_tab[0].last_hash);
			}
		}
		if (queue.found)
			printf("match: %s -> %s\n", queue.match_word, queue.match_hash);
		else
			printf("no match found for %s in [0, %lu]\n", queue.target_hash, ULONG_MAX);
	}
	else
	{
		fill_base_word_and_block(TOTAL - 1, worker_tab[0].last_word, worker_tab[0].blocks);
		sha_256_block(worker_tab[0].blocks, worker_tab[0].last_hash);
		printf("%lu: %s -> %s\n", TOTAL - 1, worker_tab[0].last_word, worker_tab[0].last_hash);
	}

	free(worker_tab);
	free(threads);
	return 0;
}
