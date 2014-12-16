#include <yajl/yajl_tree.h>
#include <yajl/yajl_parse.h>

struct stack_elem_s;
typedef struct stack_elem_s stack_elem_t;
struct stack_elem_s
{
    char * key;
    yajl_val value;
    stack_elem_t *next;
};

struct context_s
{
    stack_elem_t *stack;
    yajl_val root;
    char *errbuf;
    size_t errbuf_size;
};
typedef struct context_s context_t;

yajl_handle yajl_streaming_tree_init(context_t ctx);
yajl_val yajl_streaming_tree_get(yajl_val n, const char ** path, yajl_type type);
void yajl_streaming_tree_free (yajl_val v);
