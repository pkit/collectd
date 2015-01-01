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
 *   Sergei Turukin <sergei.turukin@rackspace.com>
 *   Vladimir Varchuk <vladimir.varchuk@rackspace.com>
 **/

#include <assert.h>

#include "collectd.h"
#if HAVE_PTHREAD_H
# include <pthread.h>
#endif

#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#include <yajl/yajl_parse.h>
#include <curl/curl.h>

#include "plugin.h"
#include "common.h"

/* Macro declarations */
/* TODO: move here all defines */
#ifndef WRITE_HTTP_DEFAULT_BUFFER_SIZE
# define WRITE_HTTP_DEFAULT_BUFFER_SIZE 4096
#endif

#define PLUGIN_NAME "write_blueflood"
#define MAX_METRIC_NAME_SIZE (6*DATA_MAX_NAME_LEN)
#define MAX_URL_SIZE 128
/* second count in day */
#define DEFAULT_TTL 24 * 60 * 60

/* used by transport */
#define CURL_SETOPT_RETURN_ERR(curl, option, parameter)\
{\
	CURLcode err;\
	if ( CURLE_OK != (err=curl_easy_setopt((curl), (option), (parameter))) )\
	{\
		ERROR("%s plugin: %s", PLUGIN_NAME, curl_easy_strerror(err));\
		return err;\
	}\
}

/* used by json generator */
#define YAJL_CHECK_RETURN_ON_ERROR(func)\
{\
	yajl_gen_status s = func;\
	if ( s!=yajl_gen_status_ok )\
	{\
		ERROR("%s error=%d", #func, s);\
		return s;\
	}\
}

#define CHECK_OPTIONAL_PARAM(str, name, section)\
	if (!str)\
	{\
		INFO("%s plugin: There is no option  %s in section %s",\
				PLUGIN_NAME, (name), (section));\
	}

#define CHECK_MANDATORY_PARAM(str, name)\
	if (!str)\
	{\
		ERROR("%s plugin: Invalid configuration. There is no option %s",\
				PLUGIN_NAME, (name));\
		return -1;\
	}

#define YAJL_ERROR_BUF_MAX_SIZE 1024

/* literals for json output */
#define STR_NAME "metricName"
#define STR_VALUE "metricValue"
#define STR_TIMESTAMP "collectionTime"
#define STR_TTL "ttlInSeconds"

/* config literals */
#define CONF_TTL STR_TTL
#define CONF_AUTH_USER "User"
#define CONF_AUTH_PASSORD "Password"
#define CONF_URL "URL"  
#define CONF_AUTH_URL "AuthURL"
#define CONF_TENANTID "TenantId"

#define BLUEFLOOD_API_VERSION "v2.0"

#define HTTP_UNAUTHORIZED 401
#define HTTP_FORBIDDEN 403
#define HTTP_OK 200
#define HTTP_SERVER_ERROR 500

/* Declarations section */
/* TODO: Move here all types, function declarations */
struct wb_transport_s;

typedef struct wb_callback_s
{
	int ttl;
	yajl_gen yajl_gen;
	/* The successfull_send flag holds 0 if last metrics send
	   attempt was successful, otherwise it's != 0.  Not zero value
	   is treated as error and write callback should not return
	   success in this case if data was not sent. And it should try
	   to resend metrics every time at read/flush callbacks. */
	int successfull_send;
	pthread_mutex_t send_lock;
} wb_callback_t;

/**************** curl transport declaration *****************/
struct blueflood_transport_interface
{
	int (*ctor)(struct blueflood_transport_interface *this);
	void (*dtor)(struct blueflood_transport_interface *this);
	int (*send)(struct blueflood_transport_interface *this, long *code);
	const char *(*last_error_text)(struct blueflood_transport_interface *this);
};

typedef struct data_s
{
	char *url;
	char *ingest_url;
} data_t;
static void free_data(data_t *data);

typedef struct auth_data_s
{
	char *auth_url;
	char *user;
	char *pass;
	char *token;
} auth_data_t;
static void free_auth_data(auth_data_t *auth_data);

struct blueflood_curl_transport_t
{
	struct blueflood_transport_interface public; /* it must be first item here */
	/* data */
	CURL *curl;
	char curl_errbuf[CURL_ERROR_SIZE];
	data_t data;
	auth_data_t auth_data;
};

/* transport functions declaration */
int transport_ctor(struct blueflood_transport_interface *this);
void transport_dtor(struct blueflood_transport_interface *this);
int transport_send(struct blueflood_transport_interface *this, long *code);
const char *transport_last_error_text(
        struct blueflood_transport_interface *this);

/* rax auth */
const char* s_blueflood_ingest_url_template =
        "%s/"BLUEFLOOD_API_VERSION"/%s/ingest";

struct MemoryStruct
{
	char *memory;
	size_t size;
};

/* Implementation section */

static void update_ingest_url(const char *tenant, const char *url, char **ingest_url)
{
	if (tenant==NULL || url==NULL) return;
	free(*ingest_url);
	*ingest_url = (char *) malloc(MAX_URL_SIZE);
	snprintf(*ingest_url, MAX_URL_SIZE, s_blueflood_ingest_url_template, url, tenant);
}

static void free_data(data_t *data)
{
	sfree(data->url);
	sfree(data->ingest_url);
}
static void free_auth_data(auth_data_t *auth_data)
{
	sfree(auth_data->auth_url);
	sfree(auth_data->user);
	sfree(auth_data->pass);
	sfree(auth_data->token);
}

static int metric_format_name(char *ret, int ret_len, const char *hostname,
        const char *plugin, const char *plugin_instance, const char *type,
        const char *type_instance, const char *name, const char* sep)
{
	const int fields_max = 6;
	char* fields[fields_max];
	int cntr = 0;
#define append(field) if ((field) && strlen(field)) fields[cntr++] = (char*)(field);
	append(hostname);
	append(plugin);
	append(plugin_instance);
	append(type);
	append(type_instance);
	append(name);
#undef append
	return strjoin(ret, ret_len, fields, cntr, sep);
}

/************* yajl json parsing implementation ************/
/* parse and retrieve key
   returned parsed value is allocated on the heap */
static char *json_get_key_alloc(const char **path, const char *buff)
{
	yajl_val node;
	static char errbuf[YAJL_ERROR_BUF_MAX_SIZE];
	char *str_val = NULL;
	char *str_val_yajl = NULL;

	if (NULL == (node = yajl_tree_parse(buff, errbuf, sizeof(errbuf))))
	{
		if (strlen(errbuf))
		{
			ERROR("%s plugin: %s", PLUGIN_NAME, errbuf);
		}
		else
		{
			ERROR("%s plugin: unknown json parsing error", PLUGIN_NAME);
		}
		return NULL;
	}
	str_val_yajl = YAJL_GET_STRING(yajl_tree_get(node, path, yajl_t_string));
	if (str_val_yajl)
		str_val = strdup(str_val_yajl);
	yajl_tree_free(node);
	return str_val;
}

/* Code was acquired from curl documentation/samples */
/* See http://curl.haxx.se/libcurl/c/getinmemory.html */
/* TODO: Replace with libyajl streaming read if possible */
static size_t curl_callback(const void *contents, size_t size, size_t nmemb,
        void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *) userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL)
	{
		ERROR("%s plugin: not enough memory", PLUGIN_NAME);
		return 0;
	}
	memcpy(&mem->memory[mem->size], contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

/* save auth header in a static variable and return */
static const char *get_auth_request(const char *user, const char *pass)
{
	static char inbuffer[WRITE_HTTP_DEFAULT_BUFFER_SIZE];
	const char* rax_auth_template =
			"{\"auth\":"
				"{\"RAX-KSKEY:apiKeyCredentials\":"
					"{\"username\":\"%s\","
					"\"apiKey\":\"%s\"}"
				"}"
			"}";

	snprintf(inbuffer, sizeof(inbuffer), rax_auth_template, user, pass);
	return inbuffer;
}
static int blueflood_request_setup(struct blueflood_curl_transport_t *transport,
		struct curl_slist **headers, const char *token,
		const char *post_data, size_t post_data_len)
{
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_NOSIGNAL, 1L);
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_USERAGENT, COLLECTD_USERAGENT"C");

	*headers = curl_slist_append(*headers, "Accept:  */*");
	*headers = curl_slist_append(*headers, "Content-Type: application/json");
	*headers = curl_slist_append(*headers, "Expect:");

	if (token != NULL)
	{
		static char token_header[MAX_URL_SIZE];
		snprintf(token_header, sizeof(token_header), "X-Auth-Token: %s", token);
		*headers = curl_slist_append(*headers, token_header);
	}

	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_HTTPHEADER, *headers);
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_ERRORBUFFER, transport->curl_errbuf);
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_URL, transport->data.ingest_url);
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_POSTFIELDSIZE, post_data_len);
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_POSTFIELDS, post_data);
	return 0;
}

static int auth_request_setup(struct blueflood_curl_transport_t *transport,
		auth_data_t *auth_data,
		struct curl_slist **headers, struct MemoryStruct *chunk)
{
	/* TODO: should expect if headers are required or not */
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_NOSIGNAL, 1L);
	/* TODO: user agent name for auth server and blueflood may be different */
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_USERAGENT, COLLECTD_USERAGENT"C");
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_ERRORBUFFER, transport->curl_errbuf);
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_URL, auth_data->auth_url);

	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_POSTFIELDS,
	        get_auth_request(auth_data->user, auth_data->pass));
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_WRITEFUNCTION, curl_callback);
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_WRITEDATA, chunk);

	*headers = curl_slist_append(*headers, "Accept:  */*");
	*headers = curl_slist_append(*headers, "Content-Type: application/json");
	*headers = curl_slist_append(*headers, "Expect:");
	CURL_SETOPT_RETURN_ERR(transport->curl, CURLOPT_HTTPHEADER, *headers);
	return 0;
}

static int auth(struct blueflood_curl_transport_t *transport, auth_data_t *auth_data)
{
	CURLcode res;
	struct MemoryStruct chunk;
	long code;
	struct curl_slist *headers = NULL;
	const char* token_xpath[] =
	{ "access", "token", "id", (const char*) 0 };

	/* prepare data for callback */
	chunk.memory = malloc(WRITE_HTTP_DEFAULT_BUFFER_SIZE);
	chunk.size = 0;

	if (!(res = auth_request_setup(transport, auth_data, &headers, &chunk)))
	{
		res = transport->public.send(&transport->public, &code);
		if (res != CURLE_OK)
		{
			ERROR("%s plugin: Auth request send error: %s", PLUGIN_NAME,
			        transport->public.last_error_text(&transport->public));
		}
		else
		{
			sfree(auth_data->token);
			auth_data->token = json_get_key_alloc(token_xpath, chunk.memory);
			if (!auth_data->token)
			{
				ERROR("%s plugin: Bad token returned", PLUGIN_NAME);
				res = -1;
			}
		}
	}

	sfree(chunk.memory);
	curl_slist_free_all(headers);
	return res;
}

/* global variables */
struct blueflood_transport_interface *s_blueflood_transport;

/************* blueflood transport implementation ************/

int transport_ctor(struct blueflood_transport_interface *this)
{
	struct blueflood_curl_transport_t *self =
	        (struct blueflood_curl_transport_t *) this;
	assert( self->curl == NULL );
	self->curl = curl_easy_init();
	if (self->curl == NULL)
	{
		strncpy(self->curl_errbuf, "libcurl: curl_easy_init failed.",
		CURL_ERROR_SIZE);
		return -1;
	}
	return 0;
}

void transport_dtor(struct blueflood_transport_interface *this)
{
	struct blueflood_curl_transport_t *self =
	        (struct blueflood_curl_transport_t *) this;
	if (self->curl != NULL)
	{
		curl_easy_cleanup(self->curl);
		self->curl = NULL;
	}
	free_data(&self->data);
	free_auth_data(&self->auth_data);
	sfree(self);
}

int transport_send(struct blueflood_transport_interface *this, long *code)
{
	struct blueflood_curl_transport_t *self =
	        (struct blueflood_curl_transport_t *) this;
	CURLcode status = 0;
	status = curl_easy_perform(self->curl);
	/* TODO: capture output as well or it will be printed to STDOUT (libcurl default) */
	if (status != CURLE_OK)
	{
		strncpy(self->curl_errbuf, "libcurl: curl_easy_perform failed.",
		CURL_ERROR_SIZE);
	}
	curl_easy_getinfo(self->curl, CURLINFO_RESPONSE_CODE, code);
	return status;
}

const char *transport_last_error_text(
        struct blueflood_transport_interface *this)
{
	struct blueflood_curl_transport_t *self =
	        (struct blueflood_curl_transport_t *) this;
	return self->curl_errbuf;
}

///////////////////////
/*
 * @param data, auth_data ownership is transfered into instance */
static struct blueflood_transport_interface* blueflood_curl_transport_alloc(
		data_t* data, auth_data_t* auth_data)
{
	struct blueflood_curl_transport_t *self = calloc(1,
	        sizeof(struct blueflood_curl_transport_t));
	self->public.ctor = transport_ctor;
	self->public.dtor = transport_dtor;
	self->public.send = transport_send;
	self->public.last_error_text = transport_last_error_text;
	self->data = *data;
	self->auth_data = *auth_data;
	if (self->public.ctor(&self->public) == 0)
		return &self->public;
	else
	{
		free(self);
		return NULL;
	}
}

void blueflood_curl_transport_free(
        struct blueflood_transport_interface **transport)
{
	if (*transport != NULL)
	{
		(*transport)->dtor(*transport);
		*transport = NULL;
	}
}

static int blueflood_curl_transport_global_initialize(long flags)
{
	/* As curl_global_init is not thread-safe it must be called only once
	 before we start using it */
	return curl_global_init(flags);
}

static void blueflood_curl_transport_global_finalize()
{
	curl_global_cleanup();
}

/************* yajl json generator implementation ************/

static int jsongen_init(yajl_gen *gen)
{
	/* free previous generator, if exists */
	if (*gen != NULL)
	{
		yajl_gen_free(*gen);
		*gen = NULL;
	}
	/* initialize yajl */
	*gen = yajl_gen_alloc(NULL);
	if (*gen != NULL)
	{
		yajl_gen_config(*gen, yajl_gen_beautify, 1);
		yajl_gen_config(*gen, yajl_gen_validate_utf8, 1);
		return 0;
	}
	else
	{
		ERROR("%s plugin: yajl_gen_alloc error", PLUGIN_NAME);
		return -1;
	}
}

static int send_json(yajl_gen *gen)
{
	const unsigned char *post_data_buf;
	size_t post_data_len;
	int request_err = 0;
	int success = -1;
	int max_attempts_count = 2;
	long code = HTTP_SERVER_ERROR;
	struct curl_slist *headers = NULL;
	struct blueflood_curl_transport_t *transport =
			(struct blueflood_curl_transport_t *) s_blueflood_transport;
	/*cache flush & free memory */
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_get_buf(*gen, &post_data_buf, &post_data_len));
	/* if we don't have any data, return success */
	if (post_data_len == 0)
	{
		WARNING("%s plugin: Empty buffer, nothing to send", PLUGIN_NAME);
		return 0;
	}
	while (request_err == 0 && max_attempts_count-- > 0 && success != 0)
	{
		/* if running auth for the first time, get auth token */
		if ( transport->auth_data.auth_url != NULL &&
		     transport->auth_data.token == NULL )
		{
			request_err = auth(transport, &transport->auth_data);
			if (request_err)
			{
				/* TODO: gracefully return from `while` loop
				 * otherwise it will cause segfault */
				ERROR("%s plugin: Authentication failed", PLUGIN_NAME);
				/* continue and handle request_error */
				continue;
			}
		}

		/* TODO: check return error */
		request_err = blueflood_request_setup(transport, &headers,
				transport->auth_data.token,
				(const char *) post_data_buf, post_data_len);
		if (request_err != 0)
		{
			/* continue and handle request_error */
			curl_slist_free_all(headers), headers = NULL;
			continue;
		}

		/* for current implementation in case of error
		 * yajl_buf will be destroyed and plugin_read
		 * will return error and it is expected that
		 * the data we did not send will be submitted again
		 * by collectd to the write callback.
		 * needs to be proven true! */
		request_err = transport->public.send(&transport->public, &code);
		curl_slist_free_all(headers), headers = NULL;
		if (request_err != 0)
		{
			ERROR("%s plugin: Metrics (len=%zu) send error: %s",
					PLUGIN_NAME, post_data_len,
					transport->public.last_error_text(
							&transport->public));
			/* continue and handle request_error */
			continue;
		}
		else
		{
			success = 0;
		}

		/* if auth_url is configured then check and handle auth errors */
		if (request_err == 0 && transport->auth_data.auth_url != NULL)
		{
			/* check if we need to reauth  */
			if (code == HTTP_UNAUTHORIZED || code == HTTP_FORBIDDEN)
			{
				/* NULL token will cause auth attempt */
				sfree(transport->auth_data.token);
				success = -1;
			}
			else if (code == HTTP_OK)
			{
				success = 0; /* OK */
			}
		}
	}

	if (success != 0 && max_attempts_count <= 0)
	{
		/* TODO: handle auth error */
		ERROR("%s plugin: Blueflood server respnsed with auth error",
				PLUGIN_NAME );
	}

	return success;
}

static yajl_gen_status gen_document_begin(yajl_gen gen)
{
	const unsigned char *buf;
	size_t len;
	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_get_buf(gen, &buf, &len));
	/* let's begin json document if not yet did it*/
	if (!len)
	{
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_array_open(gen));
	}
	return 0;
}

static yajl_gen_status gen_name_kv(yajl_gen gen, const char *metric_name)
{
	/*do not check yajl status for plain string*/
	yajl_gen_string(gen, (const unsigned char *)STR_NAME, strlen(STR_NAME));
	return yajl_gen_string(gen, (const unsigned char * )metric_name,
			       strlen(metric_name));
}

static yajl_gen_status gen_metricvalue_kv(yajl_gen gen, int type, const value_t *value)
{
	double value_double;
	int value_int;
	yajl_gen_status status=yajl_gen_status_ok;
	/*do not check yajl status for plain string*/
	yajl_gen_string(gen, (const unsigned char *)STR_VALUE, strlen(STR_VALUE));
	switch(type)
	{
	case DS_TYPE_GAUGE:
	case DS_TYPE_DERIVE:
		value_double = type==DS_TYPE_GAUGE?value->gauge:value->derive;
		if (isfinite(value_double))
			status = yajl_gen_double(gen, value_double);
		else
			status = yajl_gen_null(gen);
		break;
	case DS_TYPE_COUNTER:
	case DS_TYPE_ABSOLUTE:
		value_int = type==DS_TYPE_COUNTER?value->counter:value->absolute;
		status = yajl_gen_integer(gen, value_int);
		break;
	}
	return status;
}

static yajl_gen_status gen_notificationvalue_kv(yajl_gen gen, const char *value)
{
	/*do not check yajl status for plain string*/
	yajl_gen_string(gen, (const unsigned char *)STR_VALUE, strlen(STR_VALUE));
	return yajl_gen_string(gen, (const unsigned char *)value, strlen(value));
}

static yajl_gen_status gen_timestamp_kv(yajl_gen gen, cdtime_t t)
{
	/*do not check yajl status for plain string*/
	yajl_gen_string(gen, (const unsigned char *)STR_TIMESTAMP, strlen(STR_TIMESTAMP));
	return yajl_gen_integer(gen, CDTIME_T_TO_MS (t));
}

static yajl_gen_status gen_ttl_kv(yajl_gen gen, int ttl)
{
	/*do not check yajl status for plain string*/
	yajl_gen_string(gen, (const unsigned char *)STR_TTL, strlen(STR_TTL));
	return yajl_gen_integer(gen, ttl);
}

static int jsongen_metrics_output(wb_callback_t *cb, const data_set_t *ds,
        const value_list_t *vl)
{
	int i;
	YAJL_CHECK_RETURN_ON_ERROR(gen_document_begin(cb->yajl_gen));

	for (i = 0; i < ds->ds_num; i++)
	{
		data_source_t *data_source = &ds->ds[i];
		const value_t *value = &vl->values[i];

		/*handle any expected type*/
		if (data_source->type == DS_TYPE_GAUGE || 
		    data_source->type == DS_TYPE_DERIVE || 
		    data_source->type == DS_TYPE_COUNTER || 
		    data_source->type == DS_TYPE_ABSOLUTE )
		{
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_open(cb->yajl_gen));

			static char name_buffer[MAX_METRIC_NAME_SIZE];
			metric_format_name(name_buffer, sizeof(name_buffer), vl->host, vl->plugin,
					   vl->plugin_instance, vl->type, vl->type_instance, data_source->name, ".");

			YAJL_CHECK_RETURN_ON_ERROR(gen_name_kv(cb->yajl_gen, name_buffer));
			YAJL_CHECK_RETURN_ON_ERROR(gen_metricvalue_kv(cb->yajl_gen, data_source->type, value));
			YAJL_CHECK_RETURN_ON_ERROR(gen_timestamp_kv(cb->yajl_gen, vl->time));
			YAJL_CHECK_RETURN_ON_ERROR(gen_ttl_kv(cb->yajl_gen, cb->ttl));

			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_close(cb->yajl_gen));
		}
		else
		{
			WARNING("%s plugin: can't handle unknown ds_type=%d", 
				PLUGIN_NAME, data_source->type);
		}
	}

	return 0;
}

static int jsongen_notification_output(wb_callback_t *cb, const notification_t *notification)
{
	const char *severity_type = "";
	static char name_buffer[MAX_METRIC_NAME_SIZE];

	if ( notification->severity == NOTIF_FAILURE )
		severity_type = "OKAY";
	else if ( notification->severity == NOTIF_WARNING )
		severity_type = "WARNING";
	else
		severity_type ="FAILURE";

	YAJL_CHECK_RETURN_ON_ERROR(gen_document_begin(cb->yajl_gen));

	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_open(cb->yajl_gen));

	metric_format_name(name_buffer, sizeof(name_buffer), 
			   notification->host, 
			   notification->plugin,
			   notification->plugin_instance, 
			   notification->type, 
			   notification->type_instance, severity_type, ".");

	YAJL_CHECK_RETURN_ON_ERROR(gen_name_kv(cb->yajl_gen, name_buffer));
	YAJL_CHECK_RETURN_ON_ERROR(gen_notificationvalue_kv(cb->yajl_gen, notification->message));
	YAJL_CHECK_RETURN_ON_ERROR(gen_timestamp_kv(cb->yajl_gen, notification->time));
	YAJL_CHECK_RETURN_ON_ERROR(gen_ttl_kv(cb->yajl_gen, cb->ttl));

	YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_map_close(cb->yajl_gen));

	return 0;
}


/************* blueflood plugin implementation ************/

static void free_user_data(wb_callback_t *cb)
{
	if (!cb)
		return;

	if (cb->yajl_gen != NULL)
	{
		send_json(&cb->yajl_gen);
		/* error handling is not needed on exit, free yajl
		 memory anyway */
		yajl_gen_free(cb->yajl_gen);
	}

	/* curl transport end session & destroy */
	blueflood_curl_transport_free(&s_blueflood_transport);
	sfree(cb);
}

enum {ECollectDataMetrics, ECollectDataNotification};
static int collect_data(wb_callback_t *cb, int collect_data_type, ...)
{
	int status = -1;

	assert(collect_data_type == ECollectDataMetrics || collect_data_type == ECollectDataNotification);
	pthread_mutex_lock(&cb->send_lock);
	if (cb->successfull_send == 0) /* OK */
	{
		/*fetch variable arguments depending on data type*/
		va_list args;
		va_start(args, collect_data_type);

		if (collect_data_type == ECollectDataMetrics)
		{
			const data_set_t *ds = va_arg(args, const data_set_t *);
			const value_list_t *vl = va_arg(args, const value_list_t *);
			status = jsongen_metrics_output(cb, ds, vl);
		}
		else if (collect_data_type == ECollectDataNotification)
		{
			const notification_t *notification = va_arg(args, const notification_t *);
			status = jsongen_notification_output(cb, notification);
		}
		va_end(args);

		if (status != 0)
		{
			ERROR("%s plugin: json generating failed err=%d.", PLUGIN_NAME,
			        status);
			/* reset all data and try to continue
			 * probably encoding problem */
			status = jsongen_init(&cb->yajl_gen);
		}
	}
	pthread_mutex_unlock(&cb->send_lock);
	return (status);

}

static void wb_callback_free(void *data)
{
	INFO("%s plugin: free", PLUGIN_NAME);
	free_user_data((wb_callback_t *) data);
}

static int wb_write(const data_set_t *ds, const value_list_t *vl,
        user_data_t *user_data)
{
	return collect_data(user_data->data, ECollectDataMetrics, ds, vl);
}

static int wb_notification(const notification_t *notification, user_data_t *user_data)
{
	return collect_data(user_data->data, ECollectDataNotification, notification);
}

/* return 0 - ok, else error */
static int send_data(user_data_t *user_data)
{
	wb_callback_t *cb;
	int err = 0;
	const unsigned char *buf;
	size_t len;

	cb = user_data->data;
	pthread_mutex_lock(&cb->send_lock);
	/* finalize json structure if last send was a success */
	if (cb->successfull_send == 0) /* OK */
	{
		/* cache flush & free memory */
		YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_get_buf(cb->yajl_gen, &buf, &len));

		/* don't add anything to buffer if we don't have any data.*/
		if (len > 0)
		{
			/*end of json*/
			YAJL_CHECK_RETURN_ON_ERROR(yajl_gen_array_close(cb->yajl_gen));
		}
	}
	err = send_json(&cb->yajl_gen);
	if (err == 0) /* OK */
	{
		cb->successfull_send = 0;
		err = jsongen_init(&cb->yajl_gen);
	}
	else
	{
		/* if send was not a success then just try to
		 * resend it next time, do not free yajl
		 * resources.  All further invocations of write
		 * callback must return error at the attempt to add
		 * new data while old data is not yet sent. */
		cb->successfull_send = -1;
	}
	pthread_mutex_unlock(&cb->send_lock);
	return err;
}

static int wb_flush(cdtime_t timeout __attribute__((unused)),
        const char *identifier __attribute__((unused)), user_data_t *user_data)
{
	return send_data(user_data);
}

static int wb_read(user_data_t *user_data)
{
	return send_data(user_data);
}

static void config_get_auth_params(oconfig_item_t *child, wb_callback_t *cb,
        auth_data_t *auth_data)
{
	int i = 0;
	cf_util_get_string(child, &auth_data->auth_url);
	/* Consider empty url address as if no auth is present */
	if (strlen(auth_data->auth_url) == 0)
	{
		sfree(auth_data->auth_url);
	}
	for (i = 0; i < child->children_num; i++)
	{
		oconfig_item_t *childAuth = child->children + i;
		if (strcasecmp(CONF_AUTH_USER, childAuth->key) == 0)
			cf_util_get_string(childAuth, &auth_data->user);
		else if (strcasecmp(CONF_AUTH_PASSORD, childAuth->key) == 0)
			cf_util_get_string(childAuth, &auth_data->pass);
		else
			ERROR("%s plugin: Invalid configuration "
					"option: %s.", PLUGIN_NAME, childAuth->key);
	}
}

/*@return 0 if ok, -1 on error*/
static int config_get_url_params(oconfig_item_t *ci, wb_callback_t *cb,
        data_t *data, auth_data_t *auth_data)
{
	char *tenant = NULL;
	int auth_specified=0;
	if (strcasecmp("URL", ci->key) == 0)
	{
		cb->ttl = DEFAULT_TTL;
		cf_util_get_string(ci, &data->url);
		int i = 0;
		for (i = 0; i < ci->children_num; i++)
		{
			oconfig_item_t *child = ci->children + i;
			if (strcasecmp(CONF_TENANTID, child->key) == 0)
			{
				cf_util_get_string(child, &tenant);
				/*immediately update ingest_url*/
				update_ingest_url(tenant, data->url, &data->ingest_url);
				/*do not assign NULL after freeing to
				  check later parameter availability*/
				free(tenant);
			}
			else if (strcasecmp(CONF_TTL, child->key) == 0)
				cf_util_get_int(child, &cb->ttl);
			else if (strcasecmp(CONF_AUTH_URL, child->key) == 0)
			{
				config_get_auth_params(child, cb, auth_data);
				auth_specified=1;
			}
			else
				ERROR("%s plugin: Invalid configuration "
						"option: %s.", PLUGIN_NAME, child->key);
		}
	}
	else
	{
		ERROR("%s plugin: Invalid configuration "
				"option: %s.", PLUGIN_NAME, ci->key);
	}

	if ( auth_specified )
	{
		CHECK_MANDATORY_PARAM(auth_data->auth_url, CONF_AUTH_URL);
		CHECK_MANDATORY_PARAM(auth_data->user, CONF_AUTH_USER);
		CHECK_MANDATORY_PARAM(auth_data->pass, CONF_AUTH_PASSORD);
	}
	else
	{
		CHECK_OPTIONAL_PARAM(auth_data->auth_url, CONF_AUTH_URL, CONF_URL);
		CHECK_OPTIONAL_PARAM(auth_data->user, CONF_AUTH_USER, CONF_AUTH_URL);
		CHECK_OPTIONAL_PARAM(auth_data->pass, CONF_AUTH_PASSORD, CONF_AUTH_URL);
	}
	CHECK_MANDATORY_PARAM(data->url, CONF_URL);
	CHECK_MANDATORY_PARAM(tenant, CONF_TENANTID);
	return 0;
}

static int read_config(oconfig_item_t *ci)
{
	data_t data;
	auth_data_t auth_data;
	memset(&data, '\0', sizeof(data_t));
	memset(&auth_data, '\0', sizeof(auth_data_t));

	wb_callback_t *cb;
	user_data_t user_data;

	cb = calloc(1, sizeof(*cb));
	if (cb == NULL)
	{
		ERROR("%s plugin: malloc failed.", PLUGIN_NAME);
		return (-1);
	}

	pthread_mutex_init(&cb->send_lock, /* attr = */NULL);

	if ( config_get_url_params(ci, cb, &data, &auth_data) != 0 )
	{
		/*free data, auth_data separately while it's not yet a part of cb*/
		free_data(&data);
		free_auth_data(&auth_data);
		free_user_data(cb);
		return -1;
	}

	s_blueflood_transport = blueflood_curl_transport_alloc(&data, &auth_data);
	if (s_blueflood_transport == NULL)
	{
		ERROR("%s plugin: construct transport error", PLUGIN_NAME);
		/*free data, auth_data separately while it's not yet a part of cb*/
		free_data(&data);
		free_auth_data(&auth_data);
		free_user_data(cb);
		return -1;
	}

	/* Allocate json generator */
	cb->yajl_gen = NULL;
	if (jsongen_init(&cb->yajl_gen) != 0)
	{
		free_user_data(cb);
		return -1;
	}

	DEBUG ("%s plugin: Registering write callback with URL %s",
			PLUGIN_NAME, data.url);

	user_data.data = cb;

	/* set free_callback only once, see plugin.c source code */
	user_data.free_func = NULL;

	plugin_register_notification (PLUGIN_NAME,
				      wb_notification, 
				      &user_data);

	plugin_register_flush(PLUGIN_NAME, wb_flush, &user_data);
	/* register read plugin to ensure that data will be sent
	 * on each configured interval */
	plugin_register_complex_read(NULL, PLUGIN_NAME, wb_read, NULL, &user_data);

	user_data.free_func = wb_callback_free;
	plugin_register_write(PLUGIN_NAME, wb_write, &user_data);

	INFO("%s plugin: read/write callback registered", PLUGIN_NAME);

	return (0);
}

static int wb_config(oconfig_item_t *ci)
{
	INFO("%s plugin: config callback", PLUGIN_NAME);
	int err = 0;
	int i;
	for (i = 0; i < ci->children_num; i++)
	{
		err = read_config(ci->children + i);
	}
	return err;
}

static int wb_init(void)
{
	int curl_init_err;

	/* Call this while collectd is still single-threaded to avoid
	 * initialization issues in libgcrypt. */
	INFO("%s plugin: init", PLUGIN_NAME);

	curl_init_err = blueflood_curl_transport_global_initialize(CURL_GLOBAL_SSL);
	if (curl_init_err != 0)
	{
		/* curl init error handling */
		ERROR("%s plugin: init error::curl_global_init=%d", PLUGIN_NAME,
		        curl_init_err);
		return -1;
	}

	INFO("%s plugin: init successful", PLUGIN_NAME);
	return (0);
}

static int wb_shutdown(void)
{
	INFO("%s plugin: shutdown", PLUGIN_NAME);
	blueflood_curl_transport_global_finalize();
	INFO("%s plugin: shutdown successful", PLUGIN_NAME);
	plugin_unregister_complex_config(PLUGIN_NAME);
	plugin_unregister_init(PLUGIN_NAME);
	plugin_unregister_read(PLUGIN_NAME);
	plugin_unregister_flush(PLUGIN_NAME);
	plugin_unregister_write(PLUGIN_NAME);
	plugin_unregister_shutdown(PLUGIN_NAME);

	return 0;
}

void module_register(void)
{
	INFO("%s plugin: registered", PLUGIN_NAME);
	plugin_register_complex_config(PLUGIN_NAME, wb_config);
	plugin_register_init(PLUGIN_NAME, wb_init);
	plugin_register_shutdown(PLUGIN_NAME, wb_shutdown);
}

/* vim: set fdm=marker sw=8 ts=8 tw=78 et : */
