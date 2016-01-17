#include <stdio.h>
#include <string.h>

struct A {
	unsigned a : 4;
	unsigned b : 4;
};

int main() {
	printf("sizeof struct A %d\n", sizeof(struct A));
	struct A x;
	memcpy(&x, "0123", sizeof(x));
	printf("x.a=%u, x.b=%u, char[0]=%x\n", x.a, x.b, *((char *)&x));
	

	char v[2];
	v[0] = 0x40;
	v[1] = 0x00;
	unsigned short s;
	memcpy(&s, v, 2);
	printf("s = %u, s&0x0040=%x, s>>13=%x\n", s, s & 0x0040, s>>13);
	return 0;
}
