#ifndef _ARRAY_H
#define _ARRAY_H

#include <stdlib.h>

typedef struct {
    unsigned char *data;
    
    size_t size;
    size_t offset;
    size_t capacity;

} byte_array;

inline byte_array* byte_array_sized_new(size_t capacity);
inline int byte_array_clear(byte_array *arr);

#endif
