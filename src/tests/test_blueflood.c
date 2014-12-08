
#include <string.h>

#include "plugin.h"
#include "common.h"
#include "liboconfig/oconfig.h"

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
};

struct callbacks_blueflood s_data;
pthread_t s_write_thread;

/*copied from collectD to get rid from yet another object file*/
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
}

int plugin_register_init (const char *name,
			  plugin_init_cb callback){
    INFO ("plugin_register_init");
    s_data.callback_plugin_init_cb = callback;
}

int plugin_register_shutdown (const char *name,
			      plugin_shutdown_cb callback){
    INFO ("plugin_register_shutdown");
    s_data.callback_plugin_shutdown_cb = callback;
}

int plugin_register_write (const char *name,
			   plugin_write_cb callback, user_data_t *user_data){
    INFO ("plugin_register_write");
    s_data.user_data = *user_data;
    s_data.plugin_write_cb = callback;
}

int plugin_register_flush (const char *name,
			   plugin_flush_cb callback, user_data_t *user_data){
    INFO ("plugin_register_flush");
    s_data.user_data = *user_data;
    s_data.plugin_flush_cb = callback;
}

#include "write_blueflood.c"

/********************************************
collectD mockuped functions*/


void *write_asynchronously(void *obj){
    struct callbacks_blueflood *data = (struct callbacks_blueflood *)obj;
    data_set_t data_set;
    memset(&data_set, '\0', sizeof(data_set_t));
    data_set.ds_num = 4;
    /*TODO: figure out what dataset type means*/
    strcpy(data_set.type, "type");
    data_set.ds = malloc(sizeof(data_source_t)*data_set.ds_num);
    int i=0;
    data_set.ds[i].type = DS_TYPE_GAUGE;
    ++i;
    data_set.ds[i].type = DS_TYPE_COUNTER;
    ++i;
    data_set.ds[i].type = DS_TYPE_DERIVE;
    ++i;
    data_set.ds[i].type = DS_TYPE_ABSOLUTE;
    value_list_t value_list;
    memset(&value_list, '\0', sizeof(value_list_t));
    strcpy(value_list.host, "host");
    strcpy(value_list.plugin, "plugin");
    strcpy(value_list.type, "type");
    value_list.values_len = 4;
    value_list.time = time(NULL);
    value_list.interval = 1000000*30; //30sec
    value_list.values = malloc(sizeof(value_t)*4);
    i=0;
    value_list.values[i].gauge = 2.12345;
    ++i;
    value_list.values[i].counter = 3333;
    ++i;
    value_list.values[i].derive = 2;
    ++i;
    value_list.values[i].absolute = 2000000;
    data->plugin_write_cb( &data_set, &value_list, &data->user_data);
    return NULL;
}


int main(){
    /*create plugin*/
    module_register();
    /*run config callback*/
    int config_callback_result = s_data.callback_config(s_data.config);
    assert(config_callback_result==0);
    /*run init callback*/
    int init_callback_result = s_data.callback_plugin_init_cb();
    assert(init_callback_result==0);

    /*test writes*/
    int ret = pthread_create(&s_write_thread, NULL, write_asynchronously, &s_data);
    assert(0 == ret);
    ret = pthread_join(s_write_thread, NULL);
    assert(0 == ret);
    /*test flush*/
    s_data.plugin_flush_cb(0, "", &s_data.user_data);
    /*run free callback*/
    s_data.user_data.free_func(s_data.user_data.data);
    /*run shutdown callback*/
    s_data.callback_plugin_shutdown_cb();
}
