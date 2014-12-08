/**
 * collectd - src/write_blueflood.c
 * Copyright (C) 2009       Paul Sadauskas
 * Copyright (C) 2009       Doug MacEachern
 * Copyright (C) 2007-2014  Florian octo Forster
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
# define WRITE_HTTP_DEFAULT_BUFFER_SIZE 4096
#endif

#define PLUGIN_NAME "write_blueflood"

/*forward declarations*/
struct BufferedIOWrite;

/*
 * Private variables
 */
struct wb_callback_s
{
    char *location;

    char *user;
    char *pass;
    char *tenantid;
#define WH_FORMAT_JSON    1

    struct BufferedIOWrite* buffered_io;
    /*different yajl generators for simultaneous generation into
      separate buffers*/
    yajl_gen yajl_gen;

    char *send_buffer;
    pthread_mutex_t send_lock;
};
typedef struct wb_callback_s wb_callback_t;

#define MAX_DATA_TYPES  3
#define MAX_OFFSET      100

/*************************buffered io*************************/

/*declaration of buffer IO*/
struct BufferedIOData{
    char* buf;
    int   bufmax;
    int   cursor;
    // for read
    int   datasize;
};

/*Repurpose file output caching for networking io, ignore file handle
  as not used*/
typedef struct BufferedIOWrite{
    void (*flush_write)(struct BufferedIOWrite* self, int handle);
    int  (*write)(struct BufferedIOWrite* self, int handle, const void* data, size_t size);
    ssize_t (*write_override) (int handle, const void* data, size_t size);
    struct BufferedIOData data;
} BufferedIOWrite;

/**********************curl transport*********************/
struct blueflood_transport_interface {
    int  (*construct)(struct blueflood_transport_interface *this);
    void (*destroy)(struct blueflood_transport_interface *this);
    int  (*start_session)(struct blueflood_transport_interface *this);
    void (*end_session)(struct blueflood_transport_interface *this);
    int  (*send)(struct blueflood_transport_interface *this, const char *buffer, int len);
    const char *(*last_error_text)(struct blueflood_transport_interface *this);
};

struct blueflood_curl_transport_t{
    struct blueflood_transport_interface public; /*it is must be first item in structure*/
    //data
    CURL *curl;
    char *url;
    char curl_errbuf[CURL_ERROR_SIZE];
};

/*global variables*/
struct blueflood_transport_interface *s_blueflood_transport;

/*implementation of buffer IO*/

#define WRITE_IF_BUFFER_ENOUGH(iowrite, data, size)			\
    if ( size <= iowrite->data.bufmax - iowrite->data.cursor ){		\
	    /*buffer is enough to write data*/				\
	    memcpy( iowrite->data.buf + iowrite->data.cursor, data, size ); \
	    iowrite->data.cursor += size;				\
    }

static void buf_flush_write( BufferedIOWrite* self, int handle ){
	if ( self->data.cursor ){
		int b = self->write_override(handle, self->data.buf, self->data.cursor);
		(void)b;
		self->data.cursor = 0;
	}
}

static int buf_write(BufferedIOWrite* self, int handle, const void* data, size_t size ){
	WRITE_IF_BUFFER_ENOUGH(self, data, size)
	else{
		self->flush_write(self, handle);
		WRITE_IF_BUFFER_ENOUGH(self, data, size)
		else{
			/*write directly to fd, buffer is too small*/  
			int b = self->write_override(handle, data, size);
			return b;
		}
	}
	return size;
}

/*Create io engine with buffering facility, i/o optimizer.  alloc in
  heap, ownership is transfered*/
BufferedIOWrite* AllocBufferedIOWrite(void* buf, size_t size,
				      ssize_t (*f) (int handle, const void* data, size_t size) ){
	assert(buf);
	BufferedIOWrite* self = malloc( sizeof(BufferedIOWrite) );
	if ( self == NULL ) return NULL;
	self->data.buf = buf;
	self->data.bufmax = size;
	self->data.cursor=0;
	self->flush_write = buf_flush_write;
	self->write = buf_write;
	/*we can override std write function if passed function not NULL */
	if ( f )
	    self->write_override = f;
	else
	    self->write_override = write;
	return self;
}

/*@param handle is not using*/
ssize_t write_send(int handle, const void* data, size_t size){
	if ( (s_blueflood_transport->start_session(s_blueflood_transport)) != 0 ){
		ERROR ("%s plugin: %s", PLUGIN_NAME, 
		       s_blueflood_transport->last_error_text(s_blueflood_transport));
		return -1;
	}
	return s_blueflood_transport->send(s_blueflood_transport, data, size);
}

/*blueflood transport implementation*/

#define CURL_SETOPT_RETURN_ERR(option, parameter){			\
	    CURLcode err;						\
	    if ( CURLE_OK != (err=curl_easy_setopt(self->curl, option, parameter)) ){ \
		    return err;						\
	    }								\
    }

int transport_construct(struct blueflood_transport_interface *this ){
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	assert( self->curl == NULL );
	self->curl = curl_easy_init();
	if (self->curl == NULL){
		strncpy(self->curl_errbuf, "libcurl: curl_easy_init failed.", CURL_ERROR_SIZE );
		return -1;
	}
	return 0;
}

void transport_destroy(struct blueflood_transport_interface *this){
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	if ( self->curl != NULL ){
		curl_easy_cleanup (self->curl);
		self->curl = NULL;
	}
	free(self);
}

int transport_start_session(struct blueflood_transport_interface *this){
	struct blueflood_curl_transport_t *self = (struct blueflood_curl_transport_t *)this;
	if (self->curl == NULL){
		strncpy(self->curl_errbuf, "libcurl: curl_easy_init failed.", CURL_ERROR_SIZE );
		return -1;
	}

	CURL_SETOPT_RETURN_ERR(CURLOPT_NOSIGNAL, 1L);
	CURL_SETOPT_RETURN_ERR(CURLOPT_USERAGENT, COLLECTD_USERAGENT"C");

	struct curl_slist *headers = NULL;
	headers = curl_slist_append (headers, "Accept:  */*");
	headers = curl_slist_append (headers, "Content-Type: application/json");
	headers = curl_slist_append (headers, "Expect:");
	CURL_SETOPT_RETURN_ERR(CURLOPT_HTTPHEADER, headers);
	CURL_SETOPT_RETURN_ERR(CURLOPT_ERRORBUFFER, self->curl_errbuf);
	CURL_SETOPT_RETURN_ERR(CURLOPT_URL, self->url);

	return 0;
}

int transport_send(struct blueflood_transport_interface *this, const char *buffer, int len){
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

void transport_end_session(struct blueflood_transport_interface *this){
}

const char *transport_last_error_text(struct blueflood_transport_interface *this){
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
	struct blueflood_curl_transport_t *self = malloc(sizeof(struct blueflood_curl_transport_t));
	self->public = s_blueflood_transport_interface;
	self->url = strdup(url);
	if ( self->public.construct(&self->public) == 0 )
	    return &self->public;
	else
	    return NULL;
}

void blueflood_curl_transport_destroy(struct blueflood_transport_interface* interface){
	interface->destroy(interface);
}

int blueflood_curl_transport_global_initialize(long flags){
	/*As curl_global_init is not thread-safe it must be called a once
	  before start of using it*/
	return curl_global_init(flags);
}

void blueflood_curl_transport_global_finalize(){
	curl_global_cleanup();
}


/**************************************************************/
enum { js_str, js_int, js_dbl };
#define STR_NULL "null"
#define STR_NAME "name"
#define STR_VALUE "value"
#define STR_COUNTER "counter"
#define STR_TENANTID "tenantId"
#define STR_TIMESTAMP "timestamp"
#define STR_FLUSH_INTERVAL "flushInterval"

#define STR_COUNTERS "counters"
#define STR_GAUGES "gauges"
#define STR_DERIVES "derives"
#define STR_ABSOLUTES "derives"

#define YAJL_CHECK_RETURN_ON_ERROR(func){	\
	    yajl_gen_status s = func;		\
	    if ( s!=yajl_gen_status_ok ){	\
		    return s;			\
	    }					\
    }


static int jsongen_map_key_value(yajl_gen gen, int ds_type, 
				 const value_list_t *vl, const value_t *value)
{
	char name_buffer[5 * DATA_MAX_NAME_LEN];

	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_open(gen));
	//name's key
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
						   (const unsigned char *)STR_NAME, 
						   strlen(STR_NAME)));
	format_name(name_buffer, sizeof (name_buffer),
		    vl->host, vl->plugin, vl->plugin_instance,
		    vl->type, vl->type_instance);
	//name's value
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
						   (const unsigned char *)name_buffer, 
						   strlen(name_buffer)));
	//value' key
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
						   (const unsigned char *)STR_VALUE, 
						   strlen(STR_VALUE)));
	//value's value
	if ( ds_type == DS_TYPE_GAUGE ){

		if(isfinite (value->gauge)){
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_double(gen, value->gauge));
		}
		else{
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
								   (const unsigned char *)STR_NULL, 
								   strlen(STR_NULL)));
		}
	}
	else if ( ds_type == DS_TYPE_COUNTER ){
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_integer(gen, value->counter));
	}
	else if ( ds_type == DS_TYPE_ABSOLUTE ){
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_integer(gen, value->absolute));
	}
	else if ( ds_type == DS_TYPE_DERIVE ){
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_double(gen, value->derive));
	}
	else{
		assert(0);
	}
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_close(gen));
	return 0;
}

static int jsongen_metric_array(yajl_gen gen, char items_count, int ds_type, 
				const value_list_t *vl, const value_t *value ){
	if ( !items_count ){
		//value's value
		if ( ds_type == DS_TYPE_GAUGE ){
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
								   (const unsigned char *)STR_GAUGES, 
								   strlen(STR_GAUGES)));
		}
		else if ( ds_type == DS_TYPE_COUNTER ){
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
								   (const unsigned char *)STR_COUNTERS, 
								   strlen(STR_COUNTERS)));
		}
		else if ( ds_type == DS_TYPE_ABSOLUTE ){
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
								   (const unsigned char *)STR_ABSOLUTES, 
								   strlen(STR_ABSOLUTES)));
		}
		else if ( ds_type == DS_TYPE_DERIVE ){
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_string(gen, 
								   (const unsigned char *)STR_DERIVES, 
								   strlen(STR_DERIVES)));
		}
		else{
			assert(0);
		}
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_array_open(gen));
	}

	//map items
	jsongen_map_key_value(gen, ds_type, vl, value);

	return yajl_gen_status_ok;
}

static int wb_yajl_jsongen(wb_callback_t *cb, 
			   const data_set_t *ds, 
			   const value_list_t *vl )
{
	int overall_items_count_added=0;
	int i, k;

	const int ds_types[] = { DS_TYPE_GAUGE, DS_TYPE_COUNTER, DS_TYPE_DERIVE, DS_TYPE_ABSOLUTE };
	/* All value lists have a leading comma. The first one will be replaced with
	 * a square bracket in `format_json_finalize'. */
	for (i = 0; i < ds->ds_num; i++){
		/*use yet another loop to group metrics by type*/
		int items_count_by_type=0;
		for (k=0; k < sizeof(ds_types)/sizeof(*ds_types); k++){
			if (ds->ds[i].type == ds_types[k]){
				if (!overall_items_count_added){
					/*json beginning*/
					YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_open(cb->yajl_gen));
				}
				/*generate map and array's start, item array, increment items_count_by_type*/
				YAJL_CHECK_RETURN_ON_ERROR(jsongen_metric_array(cb->yajl_gen, items_count_by_type, 
										ds->ds[i].type, vl, &vl->values[i] ));
				++items_count_by_type, ++overall_items_count_added;
			}
		}
		if (items_count_by_type){
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_array_close( cb->yajl_gen));
		}
	} /* for ds->ds_num */

	// don't add anything to buffer if we don't have any data.
	if (overall_items_count_added){
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

		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_close(cb->yajl_gen));

		const unsigned char * buf;
		size_t len;
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_get_buf(cb->yajl_gen, &buf, &len));
		cb->buffered_io->write(cb->buffered_io, 0xF00, buf, len);
	}
	return 0;
} /* }}} int wb_value_list_to_json */
/**************************************************************/

static void wb_callback_free (void *data) /* {{{ */
{
	wb_callback_t *cb;

	if (data == NULL)
	    return;

	cb = data;

	/*cache flush & free memory */
	cb->buffered_io->flush_write(cb->buffered_io, 0xF00);
	free(cb->buffered_io);

	/*curl transport end session & destroy & finalize*/
	struct blueflood_transport_interface *bt = s_blueflood_transport;
	bt->end_session(bt);
	bt->destroy(bt);
	blueflood_curl_transport_global_finalize();

	yajl_gen_clear(cb->yajl_gen);
	yajl_gen_free(cb->yajl_gen);

	sfree (cb->location);
	sfree (cb->tenantid);
	sfree (cb->user);
	sfree (cb->pass);
	sfree (cb->send_buffer);

	sfree (cb);
} /* }}} void wb_callback_free */

static int wb_write_json (const data_set_t *ds, const value_list_t *vl, /* {{{ */
			  wb_callback_t *cb)
{
	int json_err = wb_yajl_jsongen(cb, ds, vl);
	if ( json_err ){
		ERROR ("%s plugin: json generating failed err=%d.", PLUGIN_NAME, json_err);
	}

	return (0);
} /* }}} int wb_write_json */

static int wb_write (const data_set_t *ds, const value_list_t *vl, /* {{{ */
		     user_data_t *user_data)
{       
	INFO ("%s plugin: write called", PLUGIN_NAME);
	wb_callback_t *cb;
	int status;

	if (user_data == NULL)
	    return (-EINVAL);

	cb = user_data->data; /*is it thread-safe to access user_data->data ?*/
	pthread_mutex_lock (&cb->send_lock);
	status = wb_write_json (ds, vl, cb);
	pthread_mutex_unlock (&cb->send_lock);

	INFO ("%s plugin: write OK", PLUGIN_NAME);
	return (status);
} /* }}} int wb_write */

static int wb_flush (cdtime_t timeout, /* {{{ */
		     const char *identifier __attribute__((unused)),
		     user_data_t *user_data)
{
	wb_callback_t *cb;
	int ret=0;

	if (user_data == NULL)
	    return (-EINVAL);

	cb = user_data->data; /*is it thread-safe to access user_data->data ?*/
	pthread_mutex_lock (&cb->send_lock);

	if (cb->buffered_io == NULL){
		ret=-1;
		ERROR ("%s plugin: Can't do flush, not initialized.", PLUGIN_NAME);
	}
	else{
	    cb->buffered_io->flush_write(cb->buffered_io, 0xF00);
	}
	pthread_mutex_unlock (&cb->send_lock);

	return ret;
} /* }}} int wb_flush */


static int wb_config_url (oconfig_item_t *ci) /* {{{ */
{
	INFO ("configuring the blueflood plugin");
	wb_callback_t *cb;
	user_data_t user_data;
	int i;

	cb = calloc (1, sizeof (*cb));
	if (cb == NULL){
		ERROR ("%s plugin: malloc failed.", PLUGIN_NAME);
		return (-1);
	}

	pthread_mutex_init (&cb->send_lock, /* attr = */ NULL);

	cf_util_get_string (ci, &cb->location);
	if (cb->location == NULL)
	    return (-1);

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;

		if(strcasecmp("TenantId",child->key) == 0)
		    cf_util_get_string(child, &cb->tenantid);		
		else if (strcasecmp ("User", child->key) == 0)
		    cf_util_get_string (child, &cb->user);
		else if (strcasecmp ("Password", child->key) == 0)
		    cf_util_get_string (child, &cb->pass);
		else {
			ERROR ("%s plugin: Invalid configuration "
			       "option: %s.", PLUGIN_NAME, child->key);
		}
	}

	if (!cb->tenantid || !cb->user || !cb->pass){
		return -1;
	}

	/* Allocate the buffer. */
	cb->send_buffer = malloc(WRITE_HTTP_DEFAULT_BUFFER_SIZE);

	/* Determine send_buffer_size. */
	cb->buffered_io = AllocBufferedIOWrite(cb->send_buffer, 
					       WRITE_HTTP_DEFAULT_BUFFER_SIZE,
					       write_send );
	if (cb->send_buffer == NULL || cb->buffered_io == NULL)
	    {
		    ERROR ("%s plugin: memory alloc failed.", PLUGIN_NAME);
		    wb_callback_free (cb);
		    return (-1);
	    }

	s_blueflood_transport = blueflood_curl_transport_construct(cb->location);
	if ( s_blueflood_transport == NULL ){
		ERROR ("%s plugin: construct transport error", PLUGIN_NAME );
		wb_callback_free (cb);
		return -1;
	}

	/*initialize yajl*/
	cb->yajl_gen = yajl_gen_alloc(NULL);
	yajl_gen_config(cb->yajl_gen, yajl_gen_beautify, 1);
	yajl_gen_config(cb->yajl_gen, yajl_gen_validate_utf8, 1);

	DEBUG ("%s plugin: Registering write callback with URL %s",
	       PLUGIN_NAME, cb->location);

	user_data.data = cb;
	user_data.free_func = wb_callback_free;

	plugin_register_flush (PLUGIN_NAME, wb_flush, &user_data);
	plugin_register_write (PLUGIN_NAME, wb_write, &user_data);

	INFO ("%s write callback registered", PLUGIN_NAME);

	return (0);
} /* }}} int wb_config_url */

static int wb_config (oconfig_item_t *ci) /* {{{ */
{
	INFO ("%s config callback", PLUGIN_NAME);
	int err=0;
	int i;
	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;

		if (strcasecmp ("URL", child->key) == 0){
			if ((err=wb_config_url (child)) != 0){
				ERROR ("%s plugin: Invalid configuration for [%s], "
				       "absent parameter/s",
				       PLUGIN_NAME, child->key);
			    return err;
			}
		}
		else{
			ERROR ("%s plugin: Invalid configuration "
			       "option: %s.", PLUGIN_NAME, child->key);
		}
	}

	return 0;
} /* }}} int wb_config */

static int wb_init (void) /* {{{ */
{
	/* Call this while collectd is still single-threaded to avoid
	 * initialization issues in libgcrypt. */
	INFO ("%s init", PLUGIN_NAME);

	int curl_init_err = blueflood_curl_transport_global_initialize(CURL_GLOBAL_SSL);
	if ( curl_init_err != 0 ){
		/*curl init error handling*/
		ERROR ("%s plugin init error::curl_global_init=%d", PLUGIN_NAME, curl_init_err );
		return -1;
	}

        INFO ("%s init successful", PLUGIN_NAME);
        return (0);
} /* }}} int wb_init */

static int wb_shutdown (void) /* {{{ */
{
	INFO ("%s plugin shutdown", PLUGIN_NAME);
	blueflood_curl_transport_global_finalize();
        INFO ("%s plugin shutdown successful", PLUGIN_NAME);
        return 0;
} /* }}} int wb_shutdown */

void module_register (void) /* {{{ */
{       
	INFO ("%s registered", PLUGIN_NAME);
        plugin_register_complex_config (PLUGIN_NAME, wb_config);
        plugin_register_init (PLUGIN_NAME, wb_init);
	plugin_register_shutdown (PLUGIN_NAME, wb_shutdown);
} /* }}} void module_register */

/* vim: set fdm=marker sw=8 ts=8 tw=78 et : */
