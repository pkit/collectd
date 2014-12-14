/**
 * collectd - src/write_blueflood.c
 * Copyright (C) 2009       Paul Sadauskas
 * Copyright (C) 2009       Doug MacEachern
 * Copyright (C) 2007-2014  Florian octo Forster
 * Copyright (C) 2014       Rackspace
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 *   Doug MacEachern <dougm@hyperic.com>
 *   Paul Sadauskas <psadauskas@gmail.com>
 *   Yaroslav Litvinov <yaroslav.litvinov@rackspace.com>
 **/

#include <assert.h>

#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "utils_cache.h"
#include "utils_format_json.h"

#if HAVE_PTHREAD_H
# include <pthread.h>
#endif

#include <yajl/yajl_gen.h>
#include <curl/curl.h>

#ifndef WRITE_HTTP_DEFAULT_BUFFER_SIZE
# define WRITE_HTTP_DEFAULT_BUFFER_SIZE 512
#endif

#define PLUGIN_NAME "write_blueflood"
#define MAX_METRIC_NAME_SIZE (6*DATA_MAX_NAME_LEN)

/*used by transport*/
#define CURL_SETOPT_RETURN_ERR(option, parameter){			\
	    CURLcode err;						\
	    if ( CURLE_OK != (err=curl_easy_setopt(self->curl, option, parameter)) ){ \
		    return err;						\
	    }								\
    }

/*used by json generator*/
#define YAJL_CHECK_RETURN_ON_ERROR(func){	\
	    yajl_gen_status s = func;		\
	    if ( s!=yajl_gen_status_ok ){	\
		    return s;			\
	    }					\
    }

/*literals for json output*/
#define STR_NAME "metricName"
#define STR_VALUE "metricValue"
#define STR_COUNTER "counter"
#define STR_TENANTID "tenantId"
#define STR_TIMESTAMP "collectionTime"
#define STR_FLUSH_INTERVAL "flushInterval"
#define STR_TTL "ttlInSeconds"


#define STR_COUNTERS "counters"
#define STR_GAUGES "gauges"
#define STR_DERIVES "derives"
#define STR_ABSOLUTES "absolutes"

typedef struct wb_callback_s
{
    char *url;
    char *user;
    char *pass;
    char *tenantid;
    char *ttl;

    yajl_gen yajl_gen;
    pthread_mutex_t send_lock;
} wb_callback_t;

/****************curl transport declaration*****************/
struct blueflood_transport_interface {
    int  (*construct)(struct blueflood_transport_interface *this);
    void (*destroy)(struct blueflood_transport_interface *this);
    int  (*start_session)(struct blueflood_transport_interface *this);
    void (*end_session)(struct blueflood_transport_interface *this);
    int  (*send)(struct blueflood_transport_interface *this, const char *buffer, size_t len);
    const char *(*last_error_text)(struct blueflood_transport_interface *this);
};

struct blueflood_curl_transport_t{
    struct blueflood_transport_interface public; /*it is must be first item in structure*/
    /*data*/
    CURL *curl;
    char *url;
    char curl_errbuf[CURL_ERROR_SIZE];
};

/*global variables*/
struct blueflood_transport_interface *s_blueflood_transport;

/*************blueflood transport implementation************/

static int transport_construct(struct blueflood_transport_interface *this ){
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	assert( self->curl == NULL );
	self->curl = curl_easy_init();
	if (self->curl == NULL){
		strncpy(self->curl_errbuf, "libcurl: curl_easy_init failed.", CURL_ERROR_SIZE );
		return -1;
	}
	return 0;
}

static void transport_destroy(struct blueflood_transport_interface *this){
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	if ( self->curl != NULL ){
		curl_easy_cleanup (self->curl);
		self->curl = NULL;
	}
	free(self->url);
	free(self);
}

static int transport_start_session(struct blueflood_transport_interface *this){
	struct curl_slist *headers = NULL;
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	/*do not check here for CURL object, as it checked once in constructor*/
	CURL_SETOPT_RETURN_ERR(CURLOPT_NOSIGNAL, 1L);
	CURL_SETOPT_RETURN_ERR(CURLOPT_USERAGENT, COLLECTD_USERAGENT"C");
	
	headers = curl_slist_append (headers, "Accept:  */*");
	headers = curl_slist_append (headers, "Content-Type: application/json");
	headers = curl_slist_append (headers, "Expect:");
	CURL_SETOPT_RETURN_ERR(CURLOPT_HTTPHEADER, headers);
	CURL_SETOPT_RETURN_ERR(CURLOPT_ERRORBUFFER, self->curl_errbuf);
	CURL_SETOPT_RETURN_ERR(CURLOPT_URL, self->url);

	return 0;
}

static int transport_send(struct blueflood_transport_interface *this, const char *buffer, size_t len){
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	CURLcode status = 0;

	CURL_SETOPT_RETURN_ERR(CURLOPT_POSTFIELDSIZE, len);
	CURL_SETOPT_RETURN_ERR(CURLOPT_POSTFIELDS, buffer);
	status = curl_easy_perform (self->curl);
	if (status != CURLE_OK){
		strncpy(self->curl_errbuf, "libcurl: curl_easy_perform failed.", CURL_ERROR_SIZE );
	}
	return status;
}

static void transport_end_session(struct blueflood_transport_interface *this){
	(void)this;
}

static const char *transport_last_error_text(struct blueflood_transport_interface *this){
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	return self->curl_errbuf;
}

static struct blueflood_transport_interface s_blueflood_transport_interface = {
    transport_construct,
    transport_destroy,
    transport_start_session,
    transport_end_session,
    transport_send,
    transport_last_error_text
};

struct blueflood_transport_interface* blueflood_curl_transport_construct(const char *url){
	struct blueflood_curl_transport_t *self = calloc(1, sizeof(struct blueflood_curl_transport_t));
	self->public = s_blueflood_transport_interface;
	self->url = strdup(url);
	if ( self->public.construct(&self->public) == 0 )
	    return &self->public;
	else
	    return NULL;
}

static int blueflood_curl_transport_global_initialize(long flags){
	/*As curl_global_init is not thread-safe it must be called a once
	  before start of using it*/
	return curl_global_init(flags);
}

static void blueflood_curl_transport_global_finalize(){
	curl_global_cleanup();
}

/*************yajl json generator implementation************/

static int jsongen_init(yajl_gen *gen){
	/*initialize yajl*/
	*gen = yajl_gen_alloc(NULL);
	if ( *gen != NULL ){
		yajl_gen_config(*gen, yajl_gen_beautify, 1);
		yajl_gen_config(*gen, yajl_gen_validate_utf8, 1);
		return 0;
	}
	else{
		ERROR ("%s plugin: yajl_gen_alloc error", PLUGIN_NAME );
		return -1;
	}
}

static int jsongen_map_key_value(yajl_gen gen, data_source_t *ds,
				 const value_list_t *vl, const value_t *value)
{
	char name_buffer[MAX_METRIC_NAME_SIZE];

	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_open(gen));
	/*name's key*/
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
						   (const unsigned char *)STR_NAME, 
						   strlen(STR_NAME)));
	format_name(name_buffer, sizeof (name_buffer),
		    vl->host, vl->plugin, vl->plugin_instance,
		    vl->type, vl->type_instance);
	strcat(name_buffer, "/" );
	strcat(name_buffer, ds->name);

	/*name's value*/
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
						   (const unsigned char *)name_buffer, 
						   strlen(name_buffer)));
	/*value' key*/
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
						   (const unsigned char *)STR_VALUE, 
						   strlen(STR_VALUE)));
	/*value's value*/
	if ( ds->type == DS_TYPE_GAUGE ){
		if(isfinite (value->gauge)){
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_double(gen, value->gauge));
		}
		else{
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_null(gen));
		}
	}
	else if ( ds->type == DS_TYPE_COUNTER ){
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_integer(gen, value->counter));
	}
	else if ( ds->type == DS_TYPE_ABSOLUTE ){
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_integer(gen, value->absolute));
	}
	else if ( ds->type == DS_TYPE_DERIVE ){
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_double(gen, value->derive));
	}
	else{
		WARNING ("%s plugin: can't handle unknown ds_type=%d", PLUGIN_NAME, ds->type);
	}
	return 0;
}

static int send_json_freemem(yajl_gen *gen){
	const unsigned char *buf;
	size_t len;
	/*cache flush & free memory */
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_get_buf(*gen, &buf, &len));

	/* don't add anything to buffer if we don't have any data.*/
	if (len>0){
		/*end of json*/
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_array_close(*gen));
	}

	if ( (s_blueflood_transport->start_session(s_blueflood_transport)) != 0 ){
		ERROR ("%s plugin: %s", PLUGIN_NAME, 
		       s_blueflood_transport->last_error_text(s_blueflood_transport));
		return -1;
	}

	/*cache flush & free memory */
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_get_buf(*gen, &buf, &len));

	if ( len >0 && 
	     s_blueflood_transport->send(s_blueflood_transport, (const char *)buf, len) != 0 ){
		ERROR ("%s plugin: Metrics (len=%zu) send error: %s", PLUGIN_NAME, len,
		       s_blueflood_transport->last_error_text(s_blueflood_transport));
	}
	yajl_gen_free(*gen), *gen = NULL;
	return 0;
}

static int jsongen_output(wb_callback_t *cb, 
			  const data_set_t *ds, 
			  const value_list_t *vl )
{
	static int overall_items_count_added=0;
	int i;

	const unsigned char *buf;
	size_t len;
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_get_buf(cb->yajl_gen, &buf, &len));
	if ( !len ){
		/*json beginning*/
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_array_open(cb->yajl_gen));
	}
	
	for (i = 0; i < ds->ds_num; i++){
		jsongen_map_key_value(cb->yajl_gen, &ds->ds[i], vl, &vl->values[i]);

		/*key, value pair*/
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(cb->yajl_gen,
							   (const unsigned char *)STR_TENANTID,
							   strlen(STR_TENANTID)));
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(cb->yajl_gen,
							   (const unsigned char *)cb->tenantid,
							   strlen(cb->tenantid)));
		/*key, value pair*/
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(cb->yajl_gen,
							   (const unsigned char *)STR_TIMESTAMP,
							   strlen(STR_TIMESTAMP)));
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_integer(cb->yajl_gen,
							    CDTIME_T_TO_MS (vl->time)));
		/*key, value pair*/
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(cb->yajl_gen,
							   (const unsigned char *)STR_FLUSH_INTERVAL,
							   strlen(STR_FLUSH_INTERVAL)));
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_integer(cb->yajl_gen,
							    CDTIME_T_TO_MS (vl->interval)));
		/*key, value pair*/
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(cb->yajl_gen,
							   (const unsigned char *)STR_TTL,
							   strlen(STR_TTL)));
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(cb->yajl_gen,
							   (const unsigned char *)cb->ttl,
							   strlen(cb->ttl)));

		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_close(cb->yajl_gen));
		++overall_items_count_added;
	}

	return 0;
}


/*************blueflood plugin implementation************/

static void free_user_data(wb_callback_t *cb){
	if ( !cb ) return;

	if ( cb->yajl_gen != NULL ){
	    send_json_freemem(&cb->yajl_gen);
	}

	/*curl transport end session & destroy*/
	if ( s_blueflood_transport!=NULL ){
		s_blueflood_transport->end_session(s_blueflood_transport);
		s_blueflood_transport->destroy(s_blueflood_transport);
		s_blueflood_transport = NULL;
	}

	sfree (cb->url);
	sfree (cb->tenantid);
	sfree (cb->user);
	sfree (cb->pass);
	sfree (cb->ttl);

	sfree (cb);
}

static void wb_callback_free (void *data){
	INFO ("%s plugin: free", PLUGIN_NAME);
	free_user_data((wb_callback_t *)data);
}

static int wb_write (const data_set_t *ds, const value_list_t *vl,
		     user_data_t *user_data){       
	wb_callback_t *cb;
	int status;

	if (user_data == NULL || user_data->data == NULL)
	    return (-EINVAL);

	cb = user_data->data; 
	pthread_mutex_lock (&cb->send_lock);
	status = jsongen_output(cb, ds, vl);
	if ( status != 0 ){
		ERROR ("%s plugin: json generating failed err=%d.", PLUGIN_NAME, status);
		status = -1;
	}
	pthread_mutex_unlock (&cb->send_lock);
	return (status);
}

static int wb_flush (cdtime_t timeout,
		     const char *identifier __attribute__((unused)),
		     user_data_t *user_data){
	wb_callback_t *cb;
	int ret=0;

	if (user_data == NULL || user_data->data == NULL)
	    return (-EINVAL);

	cb = user_data->data;
	pthread_mutex_lock (&cb->send_lock);
	send_json_freemem(&cb->yajl_gen);
	pthread_mutex_unlock (&cb->send_lock);
	return ret;
}


static int wb_config_url (oconfig_item_t *ci){
	wb_callback_t *cb;
	user_data_t user_data;
	int i;

	cb = calloc (1, sizeof (*cb));
	if (cb == NULL){
		ERROR ("%s plugin: malloc failed.", PLUGIN_NAME);
		return (-1);
	}

	pthread_mutex_init (&cb->send_lock, /* attr = */ NULL);

	cf_util_get_string (ci, &cb->url);

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;

		if(strcasecmp("TenantId",child->key) == 0)
		    cf_util_get_string(child, &cb->tenantid);		
		else if (strcasecmp ("User", child->key) == 0)
		    cf_util_get_string (child, &cb->user);
		else if (strcasecmp ("Password", child->key) == 0)
		    cf_util_get_string (child, &cb->pass);
		else if (strcasecmp ("ttlInSeconds", child->key) == 0)
		    cf_util_get_string (child, &cb->ttl);
		else {
			ERROR ("%s plugin: Invalid configuration "
			       "option: %s.", PLUGIN_NAME, child->key);
		}
	}

	if (!cb->tenantid || !cb->user || !cb->pass || !cb->url || !cb->ttl){
		ERROR ("%s plugin: Invalid configuration for [%s], "
		       "absent parameter/s", PLUGIN_NAME, ci->key);
		return -1;
	}

	/*Allocate CURL sending transport*/
	s_blueflood_transport = blueflood_curl_transport_construct(cb->url);
	if ( s_blueflood_transport == NULL ){
		ERROR ("%s plugin: construct transport error", PLUGIN_NAME );
		free_user_data(cb);
		return -1;
	}

	/*Allocate json generator*/
	if ( jsongen_init(&cb->yajl_gen) != 0 ){
		free_user_data(cb);
		return -1;
	}

	DEBUG ("%s plugin: Registering write callback with URL %s",
	       PLUGIN_NAME, cb->url);

	user_data.data = cb;

	/*set free_callback only once in according to plugin.c source code*/
	user_data.free_func = NULL;
	plugin_register_flush (PLUGIN_NAME, wb_flush, &user_data);

	user_data.free_func = wb_callback_free;
	plugin_register_write (PLUGIN_NAME, wb_write, &user_data);

	INFO ("%s plugin: write callback registered", PLUGIN_NAME);

	return (0);
}

static int wb_config (oconfig_item_t *ci){
	INFO ("%s plugin: config callback", PLUGIN_NAME);
	int err=0;
	int i;
	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;

		if (strcasecmp ("URL", child->key) == 0){
			if ((err=wb_config_url (child)) != 0){
				return err;
			}
		}
		else{
		    ERROR ("%s plugin: Invalid configuration", PLUGIN_NAME);
		    return -1;
		}
	}

	return 0;
}

static int wb_init (void){
	int curl_init_err;

	/* Call this while collectd is still single-threaded to avoid
	 * initialization issues in libgcrypt. */
	INFO ("%s plugin: init", PLUGIN_NAME);

	curl_init_err = blueflood_curl_transport_global_initialize(CURL_GLOBAL_SSL);
	if ( curl_init_err != 0 ){
		/*curl init error handling*/
		ERROR ("%s plugin: init error::curl_global_init=%d", PLUGIN_NAME, curl_init_err );
		return -1;
	}

	INFO ("%s plugin: init successful", PLUGIN_NAME);
	return (0);
}

static int wb_shutdown (void){
	INFO ("%s plugin: shutdown", PLUGIN_NAME);
	blueflood_curl_transport_global_finalize();
	INFO ("%s plugin: shutdown successful", PLUGIN_NAME);
	plugin_unregister_complex_config (PLUGIN_NAME);
	plugin_unregister_init (PLUGIN_NAME);
	plugin_unregister_flush (PLUGIN_NAME);
	plugin_unregister_write (PLUGIN_NAME);
	plugin_unregister_shutdown (PLUGIN_NAME);

	return 0;
}

void module_register (void){       
	INFO ("%s plugin: registered", PLUGIN_NAME);
	plugin_register_complex_config (PLUGIN_NAME, wb_config);
	plugin_register_init (PLUGIN_NAME, wb_init);
	plugin_register_shutdown (PLUGIN_NAME, wb_shutdown);
}

/* vim: set fdm=marker sw=8 ts=8 tw=78 et : */
