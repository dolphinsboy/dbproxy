#ifndef _ARRAY_H_
#define _ARRAY_H_

#include <stdlib.h>

typedef struct {
	unsigned char *data;

	int size;
	int offset;
	int capacity;

} byte_array;

inline byte_array* byte_array_sized_new(size_t capacity);
inline int byte_array_clear(byte_array *arr);

#endif
