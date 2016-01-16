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
	return 0;
}
