#include <stdio.h>
#include <stdint.h>

int main (int argc, char* argv[])
{
	uint32_t t = 0;
	uint32_t f = 0;
	uint32_t res = 0;
	uint32_t a;
	
	FILE *thousand = fopen(argv[1], "r");
	FILE *five = fopen(argv[2], "r");

	char buffer[4] = { 0, };
 
	fread(&a, sizeof(a), 1, thousand);
	
	t |= (a & 0x000000ff) << 24;
        t |= (a & 0x0000ff00) << 8;
        t |= (a & 0x00ff0000) >> 8;
        t |= (a & 0xff000000) >> 24;

	fread(&a, sizeof(a), 1, five);

	f |= (a & 0x000000ff) << 24;
        f |= (a & 0x0000ff00) << 8;
        f |= (a & 0x00ff0000) >> 8;
        f |= (a & 0xff000000) >> 24;

	res = t + f;
	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", t, t, f, f, res, res);

}

