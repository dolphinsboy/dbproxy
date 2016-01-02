#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "array.h"
#include "global.h"
#include "log.h"

inline byte_array* byte_array_sized_new(size_t capacity){
	
	if( capacity <= 0) return NULL;

	byte_array *arr;
	if( NULL == ( arr = calloc(1, sizeof(byte_array)))){
		return NULL;
	}
	if(NULL == (arr->data = malloc(capacity))){
		free(arr);
		arr = NULL;
		return NULL;
	}
	arr->capacity = capacity;
	return arr;
}

inline int byte_array_append_size(byte_array *arr, int len, int is_pow){
	
	int want_alloc;
	want_alloc = arr->capacity + len;
	
	if(is_pow == 1){
		int acc_alloc = 1;
		while( acc_alloc < want_alloc )	acc_alloc <<= 1;
		want_alloc = acc_alloc;
	}
	unsigned char *p;
	if( NULL == ( p = realloc(arr->data, want_alloc))){
		log_error(logger, "realloc memory failed, already has %d bytes, need %d bytes, no enough memory", arr->capacity, want_alloc);
		return RET_ERROR;
	}
	arr->capacity=want_alloc;
	arr->data = p;
	return RET_SUCCESS;
}
inline int byte_array_append_len(byte_array *arr, const unsigned char *data, int len){

	if( arr == NULL || NULL == data){
		log_error(logger, "append byte array failed, byte_array *arr==NULL or char *data==NULL");
		return -1;
	}else if( len <= 0){
		return 0;
	}
	if( (arr->capacity - arr->size)  < len ){
		int want_alloc = arr->size + len;
		int acc_alloc = 1;
		while( acc_alloc < want_alloc ) acc_alloc <<= 1;
		void *p = NULL;
		if( NULL == (p = realloc(arr->data,  acc_alloc ))){ // nestest pow
			log_error(logger, "realloc memory failed, already has %d bytes, need %d bytes, no enough memory", arr->capacity, acc_alloc);
			return -1;
		}
		/*
		memcpy(p, arr->data, arr->size);
		if( NULL != arr->data){
			free(arr->data);
		}*/
		arr->data = p;
		arr->capacity = acc_alloc;
	}
	memcpy(arr->data + arr->size , data, len);
	arr->size += len;
	return 0;
}

inline int byte_array_clear(byte_array *arr){
	if( NULL == arr) return -1;
	arr->size = 0;
	arr->offset = 0;
	return 0;
}
inline void byte_array_free(byte_array *arr){
	if( NULL == arr ) return;
	if( NULL != arr->data) {
	    free(arr->data);
	    arr->data = NULL;
	}
	free(arr);
	arr = NULL;
}
	
