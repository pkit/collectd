
#include <string.h>
#include <stdlib.h>

#include "plugin.h"
#include "common.h"
#include "liboconfig/oconfig.h"


extern void init_mock_test(int index);

/*in this test collectd mock & plugin linked statically */

struct callbacks_blueflood{
    int (*callback_config) (oconfig_item_t *ci);
    int (*callback_plugin_init_cb) (void);
    int (*callback_plugin_shutdown_cb) (void);
    int (*plugin_write_cb) (const data_set_t *, const value_list_t *,
			    user_data_t *);
    int (*plugin_flush_cb) (cdtime_t timeout, const char *identifier,
			    user_data_t *);
    //data
    char *type_plugin_name;
    oconfig_item_t *config;
    user_data_t user_data;
    int temp_count_data_values;
};

struct callbacks_blueflood s_data;
pthread_t s_write_thread;
pthread_t s_write_thread2;

/*copied from collectD to get rid from linking yet another object file*/
int cf_util_get_string (const oconfig_item_t *ci, char **ret_string) /* {{{ */
{
	char *string;

	if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_STRING))
	{
		ERROR ("cf_util_get_string: The %s option requires "
				"exactly one string argument.", ci->key);
		return (-1);
	}

	string = strdup (ci->values[0].value.string);
	if (string == NULL)
		return (-1);

	if (*ret_string != NULL)
		sfree (*ret_string);
	*ret_string = string;

	return (0);
}

int format_name (char *ret, int ret_len,
		const char *hostname,
		const char *plugin, const char *plugin_instance,
		const char *type, const char *type_instance)
{
  char *buffer;
  size_t buffer_size;

  buffer = ret;
  buffer_size = (size_t) ret_len;

#define APPEND(str) do {                                               \
  size_t l = strlen (str);                                             \
  if (l >= buffer_size)                                                \
    return (ENOBUFS);                                                  \
  memcpy (buffer, (str), l);                                           \
  buffer += l; buffer_size -= l;                                       \
} while (0)

  assert (plugin != NULL);
  assert (type != NULL);

  APPEND (hostname);
  APPEND ("/");
  APPEND (plugin);
  if ((plugin_instance != NULL) && (plugin_instance[0] != 0))
  {
    APPEND ("-");
    APPEND (plugin_instance);
  }
  APPEND ("/");
  APPEND (type);
  if ((type_instance != NULL) && (type_instance[0] != 0))
  {
    APPEND ("-");
    APPEND (type_instance);
  }
  assert (buffer_size > 0);
  buffer[0] = 0;

#undef APPEND
  return (0);
} /* int format_name */


/*collectD mockuped functions
********************************************/
int plugin_unregister_complex_config (const char *type){
    INFO ("plugin_unregister_complex_config");
    s_data.callback_config = NULL;
    return 0;
}

int plugin_unregister_init (const char *name){
    INFO ("plugin_unregister_init");
    s_data.callback_plugin_init_cb = NULL;
    return 0;
}

int plugin_unregister_shutdown (const char *name){
    INFO ("plugin_unregister_shutdown");
    s_data.callback_plugin_shutdown_cb = NULL;
    return 0;
}

int plugin_unregister_write (const char *name){
    INFO ("plugin_unregister_write");
    s_data.plugin_write_cb = NULL;
    return 0;
}

int plugin_unregister_flush (const char *name){
    INFO ("plugin_unregister_flush");
    s_data.plugin_flush_cb = NULL;
    return 0;
}

int plugin_register_complex_config (const char *type,
				    int (*callback) (oconfig_item_t *)){
    INFO ("plugin_register_complex_config");
    s_data.type_plugin_name = strdup(type);

    s_data.config = malloc(sizeof(oconfig_item_t));
    s_data.config->children_num = 1; //URL
    s_data.config->children = calloc(s_data.config->children_num, 
				     sizeof(oconfig_item_t) );
    int i=0;
    oconfig_item_t *config = &s_data.config->children[i];
    config->key = strdup("URL"); 
    config->values_num = 1;
    config->values = calloc(config->values_num, sizeof(oconfig_value_t));
    config->values[0].type=OCONFIG_TYPE_STRING;
    config->values[0].value.string = strdup("http://127.0.0.1:8000/");
    config->children_num = 3;
    config->children = calloc(config->children_num, 
			      sizeof(oconfig_item_t));
    int ij=0;
    oconfig_item_t *nested_config;
    nested_config = &config->children[ij];
    nested_config->key = strdup("TenantId");
    nested_config->values_num = 1;
    nested_config->values = calloc(config->values_num, 
				   sizeof(oconfig_value_t) );
    nested_config->values[0].type=OCONFIG_TYPE_STRING;
    nested_config->values[0].value.string = strdup("987654321");
    ++ij;
    nested_config = &config->children[ij];
    nested_config->key = strdup("User");
    nested_config->values_num = 1;
    nested_config->values = calloc(config->values_num, 
				   sizeof(oconfig_value_t) );
    nested_config->values[0].type=OCONFIG_TYPE_STRING;
    nested_config->values[0].value.string = strdup("foo");
    ++ij;
    nested_config = &config->children[ij];
    nested_config->key = strdup("Password");
    nested_config->values_num = 1;
    nested_config->values = calloc(config->values_num, 
				   sizeof(oconfig_value_t) );
    nested_config->values[0].type=OCONFIG_TYPE_STRING;
    nested_config->values[0].value.string = strdup("123456");
   
    s_data.callback_config = callback;
    return 0;
}

int plugin_register_init (const char *name,
			  plugin_init_cb callback){
    INFO ("plugin_register_init");
    s_data.callback_plugin_init_cb = callback;
    return 0;
}

int plugin_register_shutdown (const char *name,
			      plugin_shutdown_cb callback){
    INFO ("plugin_register_shutdown");
    s_data.callback_plugin_shutdown_cb = callback;
    return 0;
}

int plugin_register_write (const char *name,
			   plugin_write_cb callback, user_data_t *user_data){
    INFO ("plugin_register_write");
    s_data.user_data = *user_data;
    s_data.plugin_write_cb = callback;
    return 0;
}

int plugin_register_flush (const char *name,
			   plugin_flush_cb callback, user_data_t *user_data){
    INFO ("plugin_register_flush");
    s_data.user_data = *user_data;
    s_data.plugin_flush_cb = callback;
    return 0;
}

#include "write_blueflood.c"

/********************************************
collectD mockuped functions*/


void free_config(){
    int i, j;
    if ( s_data.config != NULL ){
	for (i=0; i < s_data.config->children_num; i++ ){
	    free(s_data.config->children[i].key);
	    /*always one item*/
	    free(s_data.config->children[i].values[0].value.string);
	    free(s_data.config->children[i].values);
	    for (j=0; j < s_data.config->children[i].children_num; j++){
		free(s_data.config->children[i].children[j].key);
		free(s_data.config->children[i].children[j].values[0].value.string);
		free(s_data.config->children[i].children[j].values);
	    }
	    free(s_data.config->children[i].children);
	}
	free(s_data.config->children);
	free(s_data.config), s_data.config = NULL;
	free(s_data.type_plugin_name), s_data.type_plugin_name = NULL;
    }
}

void free_dataset(data_set_t *data_set, value_list_t *value_list){
    free(data_set->ds);
    free(value_list->values);
}

void fill_data_values_set(data_set_t *data_set, value_list_t *value_list, int count){
    int type, i;
    for (i=0; i < count; i++){
	type = random() % 4; /*base types count*/
	if ( type == DS_TYPE_GAUGE){
	    strcpy(data_set->ds[i].name, "test_type");
	    data_set->ds[i].type = type;
	    value_list->values[i].gauge = 
#ifdef TEST_MOCK
		HUGE_VAL; //INFINITY
#else
	    (double)random();
#endif //TEST_MOCK
	}
#ifdef TEST_MOCK
	else{
	    data_set->ds[i].type = 100; //unknown data type
	}
#else
	else if ( type == DS_TYPE_COUNTER){
	    data_set->ds[i].type = type;
	    value_list->values[i].counter = random();
	}
	else if ( type == DS_TYPE_DERIVE){
	    data_set->ds[i].type = type;
	    value_list->values[i].derive = random();
	}
	else if ( type == DS_TYPE_ABSOLUTE){
	    data_set->ds[i].type = type;
	    value_list->values[i].absolute = random();
	}
#endif
    }
}

void *write_asynchronously(void *obj){
    struct callbacks_blueflood *data = (struct callbacks_blueflood *)obj;
    data_set_t data_set;
    int count = data->temp_count_data_values;

    memset(&data_set, '\0', sizeof(data_set_t));
    data_set.ds_num = count;
    /*TODO: figure out what dataset type means*/
    strcpy(data_set.type, "type");
    data_set.ds = malloc(sizeof(data_source_t)*data_set.ds_num);

    value_list_t value_list;
    memset(&value_list, '\0', sizeof(value_list_t));
    strcpy(value_list.host, "host");
    strcpy(value_list.plugin, "plugin");
    strcpy(value_list.type, "type");
    value_list.values_len = count;
    value_list.time = time(NULL);
    value_list.interval = 1000000*30; //30sec
    value_list.values = malloc(sizeof(value_t)*count);

    fill_data_values_set(&data_set, &value_list, data->temp_count_data_values);
    data->plugin_write_cb( &data_set, &value_list, &data->user_data);
    free_dataset(&data_set, &value_list);
    return NULL;
}

void template_begin(char expected_config_result, char expected_init_result){
    memset(&s_data, '\0', sizeof(struct callbacks_blueflood));
   /*create plugin*/
    module_register();
    /*run config callback*/
    int config_callback_result = s_data.callback_config(s_data.config);
    assert(config_callback_result==expected_config_result);
    if ( config_callback_result != 0 ) return; 
    /*run init callback*/
    int init_callback_result = s_data.callback_plugin_init_cb();
    assert(init_callback_result==expected_init_result);
}

void template_end(){
    /*run free callback*/
    s_data.user_data.free_func(s_data.user_data.data);
    s_data.user_data.data = NULL;
    /*run shutdown callback*/
    s_data.callback_plugin_shutdown_cb();
    /*free memories*/
    free_config();
}

void one_big_write();
void two_writes();
void two_hundred_writes();
void mock_test_0_construct_transport_error_curl_easy_init();
void mock_test_1_construct_transport_error_yajl_gen_alloc();
void mock_test_1_construct_transport_error_invalid_config();
void mock_test_1_construct_transport_error_invalid_config2();
void mock_test_2_init_callback_curl_global_init();
void mock_test_3_write_callback_yajl_gen_alloc();
void mock_test_4_write_callback_curl_easy_perform();
void mock_test_5_write_callback_curl_easy_setopt();

int main(){
#ifndef TEST_MOCK
    one_big_write();
    two_writes();
    two_hundred_writes();
#else
    mock_test_0_construct_transport_error_curl_easy_init();
    mock_test_1_construct_transport_error_yajl_gen_alloc();
    mock_test_1_construct_transport_error_invalid_config();
    mock_test_1_construct_transport_error_invalid_config2();
    mock_test_2_init_callback_curl_global_init();
    mock_test_3_write_callback_yajl_gen_alloc();
    mock_test_4_write_callback_curl_easy_perform();
    mock_test_5_write_callback_curl_easy_setopt();
#endif
    return 0;
}

void one_big_write(){
    template_begin(0, 0);
    /*test writes*/
    s_data.temp_count_data_values = 1000;
    int ret = pthread_create(&s_write_thread, NULL, write_asynchronously, &s_data);
    assert(0 == ret);
    ret = pthread_join(s_write_thread, NULL);
    assert(0 == ret);
    /*test flush*/
    s_data.plugin_flush_cb(0, "", &s_data.user_data);
    template_end();
    ret = s_data.plugin_write_cb(NULL, NULL, &s_data.user_data);
    assert(ret == -EINVAL);
    ret = s_data.plugin_flush_cb(0, "", &s_data.user_data);
    assert(ret == -EINVAL);
}

void two_writes(){
    template_begin(0, 0);
    /*test writes*/
    s_data.temp_count_data_values = 4;
    int ret = pthread_create(&s_write_thread, NULL, write_asynchronously, &s_data);
    assert(0 == ret);
    int ret2 = pthread_create(&s_write_thread2, NULL, write_asynchronously, &s_data);
    assert(0 == ret2);
    ret = pthread_join(s_write_thread, NULL);
    assert(0 == ret);
    ret = pthread_join(s_write_thread2, NULL);
    assert(0 == ret2);

    /*test flush*/
    s_data.plugin_flush_cb(0, "", &s_data.user_data);
    template_end();
}

void two_hundred_writes(){
    template_begin(0,0);
    int i;
    /*test writes*/
    s_data.temp_count_data_values = 10;
    for (i=0; i< 100; i++){
	int ret = pthread_create(&s_write_thread, NULL, write_asynchronously, &s_data);
	assert(0 == ret);
	int ret2 = pthread_create(&s_write_thread2, NULL, write_asynchronously, &s_data);
	assert(0 == ret2);
	ret = pthread_join(s_write_thread, NULL);
	assert(0 == ret);
	ret = pthread_join(s_write_thread2, NULL);
	assert(0 == ret2);
    }
    /*test flush*/
    s_data.plugin_flush_cb(0, "", &s_data.user_data);
    template_end();
}

#ifdef TEST_MOCK

void mock_test_0_construct_transport_error_curl_easy_init(){
    init_mock_test(0);
    template_begin(-1,0);
    free_config();
}
void mock_test_1_construct_transport_error_yajl_gen_alloc(){
    init_mock_test(1);
    template_begin(-1,0);
    free_config();
}

void mock_test_1_construct_transport_error_invalid_config(){
    init_mock_test(1);
    memset(&s_data, '\0', sizeof(struct callbacks_blueflood));
   /*create plugin*/
    module_register();

    /*inject error as absent value*/
    free(s_data.config->children[0].key);
    s_data.config->children[0].key = strdup("");

    /*run config callback*/
    int config_callback_result = s_data.callback_config(s_data.config);
    assert(config_callback_result==-1);
    free_config();
}

void mock_test_1_construct_transport_error_invalid_config2(){
    init_mock_test(1);
    memset(&s_data, '\0', sizeof(struct callbacks_blueflood));
   /*create plugin*/
    module_register();

    /*inject error as wrong key*/
    free(s_data.config->children[0].children[0].key);
    s_data.config->children[0].children[0].key = strdup("foo");

    /*run config callback*/
    int config_callback_result = s_data.callback_config(s_data.config);
    assert(config_callback_result==-1);
    free_config();
}
void mock_test_2_init_callback_curl_global_init(){
    init_mock_test(2);
    template_begin(0,-1);
    free_config();
}
void mock_test_3_write_callback_yajl_gen_alloc(){
    init_mock_test(3);
    template_begin(0,0);
    /*inject yajl_gen_alloc error inside of write*/
    init_mock_test(1);
   /*test writes*/
    s_data.temp_count_data_values = 4;
    write_asynchronously(&s_data);  /*just synchronous write*/
    template_end();
}
void mock_test_4_write_callback_curl_easy_perform(){
    init_mock_test(4);
    template_begin(0,0);
   /*test writes*/
    s_data.temp_count_data_values = 4;
    write_asynchronously(&s_data);  /*just synchronous write*/
    template_end();
}
void mock_test_5_write_callback_curl_easy_setopt(){
    init_mock_test(5);
    template_begin(0,0);
   /*test writes*/
    s_data.temp_count_data_values = 4;
    write_asynchronously(&s_data);  /*just synchronous write*/
    template_end();
}

#endif //TEST_MOCK
