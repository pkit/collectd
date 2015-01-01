#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <malloc.h>
#include <assert.h>

#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#include <yajl/yajl_parse.h>
#include <curl/curl.h>


/* curl and yajl mockuped functions
********************************************/

enum { YAJL_GEN_ALLOC=0, YAJL_GEN_CONFIG, YAJL_GEN_MAP_OPEN, YAJL_GEN_MAP_CLOSE, 
       YAJL_GEN_ARRAY_OPEN, YAJL_GEN_ARRAY_CLOSE, YAJL_GEN_STRING, YAJL_GEN_NULL, 
       YAJL_GEN_INTEGER, YAJL_GEN_DOUBLE, YAJL_GEN_GET_BUF, CURL_EASY_SETOPT, 
       CURL_EASY_INIT, CURL_EASY_PERFORM, CURL_GLOBAL_INIT, YAJL_TREE_PARSE, 
       YAJL_TREE_GET, CURL_EASY_STRERROR, CURL_EASY_GETINFO, MALLOC, CALLOC, REALLOC,
       MOCKS_COUNT
};


/* test data */
int test_10_flag=0;
int s_yajl_buf_len=0;
char s_buffer[] = {"emulate test json"};
struct yajl_val_s yajl_val_string = { yajl_t_string, 
				      .u = {.string = s_buffer
	}
};
void *s_curl_callback_user_data=NULL;
size_t (*s_curl_callback)(const void *contents, size_t size, size_t nmemb, void *userp)=NULL;

/* table of functions results */
#define BUF (intptr_t)&yajl_val_string
#define MOCK_VALUES_COUNT 13
#define NOMEMORY 1
#define ER0 0
#define ER1 1
#define ER2 -1
const intptr_t s_mocks_logic_matrix[MOCKS_COUNT][MOCK_VALUES_COUNT] = {
	/* tests by indexes
	 #0, #1, #2, #3, #4, #5, #6, #7, #8, #9, #10, #11,#12 */
	{ 1, ER0, 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1}, /* YAJL_GEN_ALLOC;  0:error, 1:ok */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_CONFIG */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_MAP_OPEN */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_MAP_CLOSE */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_ARRAY_OPEN */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_ARRAY_CLOSE */
	{ 0,  0,  0,ER1,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_STRING; 0:ok, 1:error */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_NULL */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_INTEGER */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_DOUBLE */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* YAJL_GEN_GET_BUF; 0:ok, -1:error */
	{ 0,  0,  0,  0,  0,ER2,  0,  0,  0,  0,  0,  0,  0}, /* CURL_EASY_SETOPT; 0:ok, -1:error */
	{ER0, 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1}, /* CURL_EASY_INIT;   0:error, 1:ok */
	{ 0,  0,  0,  0,ER1,  0,  0,  0,  0,  0,  0,  0,ER1}, /* CURL_EASY_PERFORM 0:ok, 1:error */
	{ 0,  0,ER2,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* CURL_GLOBAL_INIT; 0:ok, -1:error */
	{ER0,ER0,ER0,ER0,ER0,ER0, 1,  1,ER0,ER0,  1,  1,  1}, /* YAJL_TREE_PARSE; 1:ok, 0:error */
	{ 0,  0,  0,  0,  0,  0, BUF, BUF,0,  0,BUF, BUF,BUF}, /* YAJL_TREE_GET; BUF:ok, 0:error */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* CURL_EASY_STRERROR */
	{ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},  /* CURL_EASY_GETINFO */
	{ 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1}, /* MALLOC; 1:return real ptr, 0:error */
	{ 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,ER0,  1}, /* CALLOC; 1:return real ptr, 0:error */
	{ 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,ER0}  /* REALLOC; 1:return real ptr, 0:error */
};
int s_test_index=0;
int s_allocated_pointers_count = 0;

void init_mock_test(int index) {
	s_test_index=index;
	test_10_flag=0;
}
yajl_gen yajl_gen_alloc (const yajl_alloc_funcs *allocFuncs){
	yajl_gen v = (yajl_gen)s_mocks_logic_matrix[YAJL_GEN_ALLOC][s_test_index];
	(void)allocFuncs;
	s_yajl_buf_len=0;
	if ( v!=0 )
		++s_allocated_pointers_count; /*memory leaks test*/
	return v;
}
int yajl_gen_config (yajl_gen g, yajl_gen_option opt,...){
	(void)g;
	(void)opt;
	return (int)s_mocks_logic_matrix[YAJL_GEN_CONFIG][s_test_index];
}
yajl_gen_status yajl_gen_integer (yajl_gen hand, long long int number){
	(void)hand;
	(void)number;
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_INTEGER][s_test_index];
}
yajl_gen_status yajl_gen_double (yajl_gen hand, double number){
	(void)hand;
	(void)number;
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_DOUBLE][s_test_index];
}
yajl_gen_status yajl_gen_string (yajl_gen hand, const unsigned char *str, size_t len){
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_STRING][s_test_index];
}
 
yajl_gen_status yajl_gen_null (yajl_gen hand){
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_NULL][s_test_index];
	(void)hand;
}
 
yajl_gen_status yajl_gen_map_open (yajl_gen hand){
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_MAP_OPEN][s_test_index];
	(void)hand;
}
 
yajl_gen_status yajl_gen_map_close (yajl_gen hand){
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_MAP_CLOSE][s_test_index];
	(void)hand;
}
 
yajl_gen_status yajl_gen_array_open (yajl_gen hand){
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_ARRAY_OPEN][s_test_index];
	(void)hand;
}
 
yajl_gen_status yajl_gen_array_close (yajl_gen hand){
	++s_yajl_buf_len;
	return (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_ARRAY_CLOSE][s_test_index];
	(void)hand;
}
yajl_gen_status yajl_gen_get_buf (yajl_gen hand, const unsigned char **buf, size_t *len){
	yajl_gen_status status =  (yajl_gen_status)s_mocks_logic_matrix[YAJL_GEN_GET_BUF][s_test_index];
	if (status==0)
	{
		/* emulate buffer data */
		*buf = (unsigned char *)s_buffer;
		*len = s_yajl_buf_len;
	}
	(void)hand;
	(void)buf;
	(void)len;
	return status;
}
void yajl_gen_clear (yajl_gen hand){
	(void)hand;
}
void yajl_gen_free (yajl_gen handle){
	s_allocated_pointers_count--;
	(void)handle;
}

yajl_val yajl_tree_parse(const char *input, char *error_buffer, size_t error_buffer_size){
	yajl_val v = (yajl_val)s_mocks_logic_matrix[YAJL_TREE_PARSE][s_test_index];
	if (s_test_index == 9)
	{
		strcpy (error_buffer, s_buffer);
	}
	if (v!=0)
		++s_allocated_pointers_count;
	(void)input;
	(void)error_buffer;
	(void)error_buffer_size;
	return v;
}

yajl_val yajl_tree_get(yajl_val parent, const char **path, yajl_type type){
	yajl_val res = (yajl_val)s_mocks_logic_matrix[YAJL_TREE_GET][s_test_index];
	(void)parent;
	(void)path;
	(void)type;
	return res;
}

void yajl_tree_free(yajl_val v){
	--s_allocated_pointers_count;
	(void)v;
}


#undef curl_easy_setopt
CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...){
	CURLcode res = s_mocks_logic_matrix[CURL_EASY_SETOPT][s_test_index];
	(void)handle;
	(void)option;
	if ( res == 0 ){
		if (option==CURLOPT_WRITEFUNCTION){
			va_list args;
			va_start(args, option);
			s_curl_callback = va_arg(args, void*);
			va_end(args);
		}
		else if (option==CURLOPT_WRITEDATA){
			va_list args;
			va_start(args, option);
			s_curl_callback_user_data = va_arg(args, void*);
			va_end(args);
		}
		
	}
	return res;
}
CURL *curl_easy_init( ){
	return (CURL *)s_mocks_logic_matrix[CURL_EASY_INIT][s_test_index];
}
void curl_easy_cleanup(CURL * handle ){
	(void)handle;
}
struct curl_slist *curl_slist_append(struct curl_slist * list, const char * string ){
	(void)list;
	(void)string;
	return NULL;
}
CURLcode curl_easy_perform(CURL * easy_handle ){
	(void)easy_handle;
	CURLcode res = s_mocks_logic_matrix[CURL_EASY_PERFORM][s_test_index];
	if (s_curl_callback!=NULL)
	{
		const char contents[] = "pseudo json";
		size_t callback_res = s_curl_callback(contents, sizeof(contents), 1, s_curl_callback_user_data);
		if (s_test_index == 12)
		{
			/*this test injected alloc error and it's expected callback return 0*/
			assert(callback_res!=sizeof(contents));
			res = CURLE_WRITE_ERROR;
		}
	}
	return res;
}
CURLcode curl_global_init(long flags ){
	(void)flags;
	return s_mocks_logic_matrix[CURL_GLOBAL_INIT][s_test_index];
}
void curl_global_cleanup(void){
}

const char *curl_easy_strerror(CURLcode errornum){
	return NULL;
}

void curl_slist_free_all(struct curl_slist * list){
	(void)list;
	s_curl_callback_user_data=NULL;
	s_curl_callback=NULL;
}

#undef curl_easy_getinfo
CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...){
	if (info==CURLINFO_RESPONSE_CODE){
		va_list args;
		va_start(args, info);
		long *code = va_arg(args, long*);
		*code = 200;
		if ( test_10_flag != 0 )
		{
			/*for second invocation of mocked func*/
			*code = 401;
		}
		va_end(args);
	}
	if (s_test_index == 10)
	{
		/*inject error into curl_easy_getinfo, next invocation
		  should fail*/
		test_10_flag = 1; 
	}
	return s_mocks_logic_matrix[CURL_EASY_GETINFO][s_test_index];
	(void)curl;
	(void)info;
}

/********************************************
 * curl and yajl mockuped functions */

void *__libc_malloc(size_t size);
void *malloc(size_t size)
{
	if (!s_mocks_logic_matrix[MALLOC][s_test_index]) 
		return NULL;
	else
	{
		++s_allocated_pointers_count;
		return __libc_malloc(size);
	}
}

void __libc_free(void *ptr);
void free(void *ptr)
{
	--s_allocated_pointers_count;
	__libc_free(ptr);
}

void *__libc_calloc(size_t nmemb, size_t size);
void *calloc(size_t nmemb, size_t size)
{
	if (!s_mocks_logic_matrix[CALLOC][s_test_index]) 
		return NULL;
	else
	{
		++s_allocated_pointers_count;
		return __libc_calloc(nmemb, size);
	}

}

void *__libc_realloc(void *ptr, size_t size);
void *realloc(void *ptr, size_t size)
{
	if (!s_mocks_logic_matrix[REALLOC][s_test_index])
		return NULL;
	else
	{
		return __libc_realloc(ptr, size);
	}
}


void test_memory_leaks()
{
	assert(s_allocated_pointers_count<=0);
}
