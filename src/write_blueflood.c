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

#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "utils_cache.h"
#include "utils_format_json.h"

#if HAVE_PTHREAD_H
# include <pthread.h>
#endif

#include <curl/curl.h>

#ifndef WRITE_HTTP_DEFAULT_BUFFER_SIZE
# define WRITE_HTTP_DEFAULT_BUFFER_SIZE 4096
#endif

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

        CURL *curl;
        char curl_errbuf[CURL_ERROR_SIZE];

        char  *send_buffer;
        size_t send_buffer_size;
        size_t send_buffer_free;
        size_t send_buffer_fill;
        cdtime_t send_buffer_init_time;

        pthread_mutex_t send_lock;
};
typedef struct wb_callback_s wb_callback_t;

#define MAX_DATA_TYPES  3
#define MAX_OFFSET      100
static int wb_json_escape_string (char *buffer, size_t buffer_size, /* {{{ */
                const char *string)
{
        size_t src_pos;
        size_t dst_pos;

        if ((buffer == NULL) || (string == NULL))
                return (-EINVAL);

        if (buffer_size < 3)
                return (-ENOMEM);

        dst_pos = 0;

#define BUFFER_ADD(c) do { \
        if (dst_pos >= (buffer_size - 1)) { \
                buffer[buffer_size - 1] = 0; \
                return (-ENOMEM); \
        } \
        buffer[dst_pos] = (c); \
        dst_pos++; } while (0)

        /* Escape special characters */
        BUFFER_ADD ('"');
        for (src_pos = 0; string[src_pos] != 0; src_pos++)
        {
                if ((string[src_pos] == '"')
                                || (string[src_pos] == '\\'))
                {
                        BUFFER_ADD ('\\');
                        BUFFER_ADD (string[src_pos]);
                }
                else if (string[src_pos] <= 0x001F)
                        BUFFER_ADD ('?');
                else
                        BUFFER_ADD (string[src_pos]);
        } /* for */
        BUFFER_ADD ('"');
        buffer[dst_pos] = 0;

#undef BUFFER_ADD

        return (0);
} /* }}} int wb_json_escape_string */

 static int wb_value_list_to_json (char *buffer, size_t buffer_size, /* {{{ */
                const data_set_t *ds, const value_list_t *vl, const char *tenantid)
{
        size_t offset = 0;
        char temp[512] = {0};
        char name_buffer[5 * DATA_MAX_NAME_LEN];
        int status;
        int store[MAX_DATA_TYPES][MAX_OFFSET]; 
        int gauge_offset = 0;
        int counter_offset = 0;
        int absolute_offset = 0;
        gauge_t *rates = NULL;
        int i;

        memset (buffer, 0, buffer_size);

#define BUFFER_ADD(...) do { \
        status = ssnprintf (buffer + offset, buffer_size - offset, \
                        __VA_ARGS__); \
        if (status < 1) \
        return (-1); \
        else if (((size_t) status) >= (buffer_size - offset)) \
        return (-ENOMEM); \
        else \
        offset += ((size_t) status); } while (0)

#define BUFFER_ADD_KEYVAL(key, value) do { \
        status = wb_json_escape_string (temp, sizeof (temp), (value)); \
        if (status != 0) \
        return (status); \
        BUFFER_ADD ("\"%s\":%s,", (key), temp); } while (0)

        /* All value lists have a leading comma. The first one will be replaced with
         * a square bracket in `format_json_finalize'. */
        for (i = 0; i < ds->ds_num; i++)
        {
                if (ds->ds[i].type == DS_TYPE_GAUGE)
                {		
                        store[0][gauge_offset] = i;
                        gauge_offset++;
                }
                else if (ds->ds[i].type == DS_TYPE_COUNTER) 
                {
                        store[1][counter_offset] = i;
                        counter_offset++;
                }
                else if (ds->ds[i].type == DS_TYPE_DERIVE) 
                {
                        DEBUG ("Skipping derive data type for now");
                }
                else if (ds->ds[i].type == DS_TYPE_ABSOLUTE) 
                {
                        store[2][absolute_offset] = i;
                        absolute_offset++;
                }
                else
                {
                        ERROR ("format_json: Unknown data source type: %i",
                                        ds->ds[i].type);
                        sfree (rates);
                        return (-1);
                }
        } /* for ds->ds_num */

        // don't add anything to buffer if we don't have any data.
        if (gauge_offset == 0 && counter_offset == 0 && absolute_offset == 0)
                return 0;

        BUFFER_ADD ("{");
        if (counter_offset > 0) 
        {
                BUFFER_ADD ("\"counters\":[");
                for (i = 0; i < counter_offset; i++) {
                        INFO ("ADDING COUNTER TO BUFFER"); // TODO These debug statements need to be removed during cleanup
                        BUFFER_ADD ("{");
                        format_name(name_buffer, sizeof (name_buffer),
                                        vl->host, vl->plugin, vl->plugin_instance,
                                        vl->type, vl->type_instance);
                        BUFFER_ADD_KEYVAL ("name", name_buffer);
                        BUFFER_ADD ("\"value\":%llu", vl->values[store[1][i]].counter);
                        BUFFER_ADD ("},");
                }
                offset--;
                BUFFER_ADD ("],");
                INFO ("format_json: value_list_to_json: buffer = %s;", buffer);
        }

        if (gauge_offset > 0) 
        {
                INFO ("format_json: value_list_to_json: buffer = %s;", buffer);
                BUFFER_ADD ("\"gauges\":[");
                for (i = 0; i < gauge_offset; i++) 
                {
                        INFO ("ADDED GAUGE as %s, metric value as %g", vl->plugin, vl->values[store[0][i]].gauge);
                        BUFFER_ADD ("{");
                        format_name(name_buffer, sizeof (name_buffer),
                                        vl->host, vl->plugin, vl->plugin_instance,
                                        vl->type, vl->type_instance);
                        BUFFER_ADD_KEYVAL ("name", name_buffer);
                        if(isfinite (vl->values[store[0][i]].gauge)) 
                        {
                                BUFFER_ADD ("\"value\":%g", vl->values[store[0][i]].gauge);
                        }
                        else 
                        {
                                BUFFER_ADD ("\"value\":null");
                        }
                        BUFFER_ADD ("},");
                }
                offset--;
                BUFFER_ADD ("],");
                INFO ("format_json: value_list_to_json: buffer = %s;", buffer);
        }

        if (absolute_offset > 0) 
        {
                INFO ("format_json: value_list_to_json: buffer = %s;", buffer);
                BUFFER_ADD ("\"gauges\":[");
                for (i = 0; i < absolute_offset; i++) {
                        INFO ("ADDING ABSOLUTE tO BUFFER");
                        BUFFER_ADD ("{");
                        format_name(name_buffer, sizeof (name_buffer),
                                        vl->host, vl->plugin, vl->plugin_instance,
                                        vl->type, vl->type_instance);
                        BUFFER_ADD_KEYVAL ("name", name_buffer);
                        BUFFER_ADD ("\"value\":%"PRIu64"},", vl->values[store[2][i]].absolute);
                        BUFFER_ADD ("},");
                }
                offset--;
                BUFFER_ADD ("],");
                INFO ("format_json: value_list_to_json: buffer = %s;", buffer);
        }

        BUFFER_ADD("\"tenantId\":\"%s\",",tenantid);
        BUFFER_ADD ("\"timestamp\":%lu,", CDTIME_T_TO_MS (vl->time));
        BUFFER_ADD ("\"flushInterval\":%lu", CDTIME_T_TO_MS (vl->interval));
        BUFFER_ADD ("}");
#undef BUFFER_ADD
#undef BUFFER_ADD_KEYVAL

        DEBUG ("format_json: value_list_to_json: buffer = %s;", buffer);

        return (0);
} /* }}} int wb_value_list_to_json */

static int wb_format_json_value_list_nocheck (char *buffer, /* {{{ */
                size_t *ret_buffer_fill, size_t *ret_buffer_free,
                const data_set_t *ds, const value_list_t *vl,
                size_t temp_size, const char *tenantid)
{
        char temp[temp_size];
        int status;

        status = wb_value_list_to_json (temp, sizeof (temp), ds, vl, tenantid);
        if (status != 0)
                return (status);
        temp_size = strlen (temp);

        memcpy (buffer + (*ret_buffer_fill), temp, temp_size + 1);
        (*ret_buffer_fill) += temp_size;
        (*ret_buffer_free) -= temp_size;

        return (0);
} /* }}} int format_json_value_list_nocheck */

static int wb_format_json_value_list (char *buffer, /* {{{ */
                size_t *ret_buffer_fill, size_t *ret_buffer_free,
                const data_set_t *ds, const value_list_t *vl, const char *tenantid)
{
        if ((buffer == NULL)
                        || (ret_buffer_fill == NULL) || (ret_buffer_free == NULL)
                        || (ds == NULL) || (vl == NULL))
                return (-EINVAL);

        if (*ret_buffer_free < 3)
                return (-ENOMEM);

        return (wb_format_json_value_list_nocheck (buffer,
                                ret_buffer_fill, ret_buffer_free, ds, vl,
                                (*ret_buffer_free) - 2, tenantid));
} /* }}} int format_json_value_list */

static void wb_reset_buffer (wb_callback_t *cb)  /* {{{ */
{
        memset (cb->send_buffer, 0, cb->send_buffer_size);
        cb->send_buffer_free = cb->send_buffer_size;
        cb->send_buffer_fill = 0;
        cb->send_buffer_init_time = cdtime ();

        format_json_initialize (cb->send_buffer,
                        &cb->send_buffer_fill,
                        &cb->send_buffer_free);
} /* }}} wb_reset_buffer */

int wb_format_json_finalize (char *buffer, /* {{{ */
                size_t *ret_buffer_fill, size_t *ret_buffer_free)
{
        size_t pos;

        if ((buffer == NULL) || (ret_buffer_fill == NULL) || (ret_buffer_free == NULL))
                return (-EINVAL);

        if (*ret_buffer_free < 2)
                return (-ENOMEM);

        pos = *ret_buffer_fill;
        buffer[pos] = 0;

        INFO ("write_blueflood plugin: In finalize method %s", buffer);

        (*ret_buffer_fill)++;
        (*ret_buffer_free)--;

        return (0);
}  /* }}} int wb_format_json_finalize */

static int wb_send_buffer (wb_callback_t *cb) /* {{{ */
{
        int status = 0;

        curl_easy_setopt (cb->curl, CURLOPT_POSTFIELDS, cb->send_buffer);
        status = curl_easy_perform (cb->curl);
        if (status != CURLE_OK)
        {
                ERROR ("write_blueflood plugin: curl_easy_perform failed with "
                                "status %i: %s",
                                status, cb->curl_errbuf);
        }
        return (status);
} /* }}} wb_send_buffer */

static int wb_callback_init (wb_callback_t *cb) /* {{{ */
{
        struct curl_slist *headers;

        if (cb->curl != NULL)
                return (0);

        cb->curl = curl_easy_init ();
        if (cb->curl == NULL)
        {
                ERROR ("curl plugin: curl_easy_init failed.");
                return (-1);
        }

        curl_easy_setopt (cb->curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt (cb->curl, CURLOPT_USERAGENT, COLLECTD_USERAGENT);

        headers = NULL;
        headers = curl_slist_append (headers, "Accept:  */*");
        headers = curl_slist_append (headers, "Content-Type: application/json");
        headers = curl_slist_append (headers, "Expect:");
        curl_easy_setopt (cb->curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt (cb->curl, CURLOPT_ERRORBUFFER, cb->curl_errbuf);
        curl_easy_setopt (cb->curl, CURLOPT_URL, cb->location);

        wb_reset_buffer (cb);

        return (0);
} /* }}} int wb_callback_init */

static int wb_flush_nolock (cdtime_t timeout, wb_callback_t *cb) /* {{{ */
{
        int status;

        DEBUG ("write_blueflood plugin: wb_flush_nolock: timeout = %.3f; "
                        "send_buffer_fill = %zu;",
                        CDTIME_T_TO_DOUBLE (timeout),
                        cb->send_buffer_fill);

        /* timeout == 0  => flush unconditionally */
        if (timeout > 0)
        {
                cdtime_t now;

                now = cdtime ();
                if ((cb->send_buffer_init_time + timeout) > now)
                        return (0);
        }

        if (cb->send_buffer_fill <= 2)
        {
                cb->send_buffer_init_time = cdtime ();
                return (0);
        }

        status = wb_format_json_finalize (cb->send_buffer,
                        &cb->send_buffer_fill,
                        &cb->send_buffer_free);
        if (status != 0)
        {
                ERROR ("write_blueflood: wb_flush_nolock: "
                                "wb_format_json_finalize failed.");
                wb_reset_buffer (cb);
                return (status);
        }

        status = wb_send_buffer (cb);
        wb_reset_buffer (cb);

        return (status);
} /* }}} wb_flush_nolock */

static int wb_flush (cdtime_t timeout, /* {{{ */
                const char *identifier __attribute__((unused)),
                user_data_t *user_data)
{
        wb_callback_t *cb;
        int status;

        if (user_data == NULL)
                return (-EINVAL);

        cb = user_data->data;

        pthread_mutex_lock (&cb->send_lock);

        if (cb->curl == NULL)
        {
                status = wb_callback_init (cb);
                if (status != 0)
                {
                        ERROR ("write_blueflood plugin: wb_callback_init failed.");
                        pthread_mutex_unlock (&cb->send_lock);
                        return (-1);
                }
        }

        status = wb_flush_nolock (timeout, cb);
        pthread_mutex_unlock (&cb->send_lock);

        return (status);
} /* }}} int wb_flush */

static void wb_callback_free (void *data) /* {{{ */
{
        wb_callback_t *cb;

        if (data == NULL)
                return;

        cb = data;

        wb_flush_nolock (/* timeout = */ 0, cb);

        if (cb->curl != NULL)
        {
                curl_easy_cleanup (cb->curl);
                cb->curl = NULL;
        }
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
        int status;
        int format_status;

        pthread_mutex_lock (&cb->send_lock);

        if (cb->curl == NULL)
        {
                status = wb_callback_init (cb);
                if (status != 0)
                {
                        ERROR ("write_blueflood plugin: wb_callback_init failed.");
                        pthread_mutex_unlock (&cb->send_lock);
                        return (-1);
                }
        }

        format_status = wb_format_json_value_list (cb->send_buffer,
                        &cb->send_buffer_fill,
                        &cb->send_buffer_free,
                        ds, vl, cb->tenantid);

        if (format_status == (-ENOMEM))
        {
                ERROR("write_blueflood plugin: no memory available");
                return -1;
        }

        if (cb->send_buffer_fill > 0) {
                status = wb_flush_nolock (/* timeout = */ 0, cb);
                if (status != 0)
                {
                        wb_reset_buffer (cb);
                        pthread_mutex_unlock (&cb->send_lock);
                        return (status);
                }
        }

        DEBUG ("write_blueflood plugin: <%s> buffer %zu/%zu (%g%%)",
                        cb->location,
                        cb->send_buffer_fill, cb->send_buffer_size,
                        100.0 * ((double) cb->send_buffer_fill) / ((double) cb->send_buffer_size));

        /* Check if we have enough space for this command. */
        pthread_mutex_unlock (&cb->send_lock);

        return (0);
} /* }}} int wb_write_json */

static int wb_write (const data_set_t *ds, const value_list_t *vl, /* {{{ */
                user_data_t *user_data)
{       
        INFO ("write of bluelood write plugin called");
        wb_callback_t *cb;
        int status;

        if (user_data == NULL)
                return (-EINVAL);

        cb = user_data->data;

        status = wb_write_json (ds, vl, cb);

        return (status);
} /* }}} int wb_write */

static int wb_config_url (oconfig_item_t *ci) /* {{{ */
{
        INFO ("configuring the blueflood plugin");
        wb_callback_t *cb;
        int buffer_size = 0;
        user_data_t user_data;
        int i;

        cb = malloc (sizeof (*cb));
        if (cb == NULL)
        {
                ERROR ("write_blueflood plugin: malloc failed.");
                return (-1);
        }
        memset (cb, 0, sizeof (*cb));

        pthread_mutex_init (&cb->send_lock, /* attr = */ NULL);

        cf_util_get_string (ci, &cb->location);
        if (cb->location == NULL)
                return (-1);

        for (i = 0; i < ci->children_num; i++)
        {
                oconfig_item_t *child = ci->children + i;

                if(strcasecmp("TenantId",child->key) == 0)
                        cf_util_get_string(child, &cb->tenantid);		
                else if (strcasecmp ("User", child->key) == 0)
                        cf_util_get_string (child, &cb->user);
                else if (strcasecmp ("Password", child->key) == 0)
                        cf_util_get_string (child, &cb->pass);
                else
                {
                        ERROR ("write_blueflood plugin: Invalid configuration "
                                        "option: %s.", child->key);
                }
        }

        /* Determine send_buffer_size. */
        cb->send_buffer_size = WRITE_HTTP_DEFAULT_BUFFER_SIZE;
        if (buffer_size >= 1024)
                cb->send_buffer_size = (size_t) buffer_size;
        else if (buffer_size != 0)
                ERROR ("write_blueflood plugin: Ignoring invalid BufferSize setting (%d).",
                                buffer_size);

        /* Allocate the buffer. */
        cb->send_buffer = malloc (cb->send_buffer_size);
        if (cb->send_buffer == NULL)
        {
                ERROR ("write_blueflood plugin: malloc(%zu) failed.", cb->send_buffer_size);
                wb_callback_free (cb);
                return (-1);
        }
        /* Nulls the buffer and sets ..._free and ..._fill. */
        wb_reset_buffer (cb);

        DEBUG ("write_blueflood: Registering write callback with URL %s",
                        cb->location);

        memset (&user_data, 0, sizeof (user_data));
        user_data.data = cb;
        user_data.free_func = NULL;
        plugin_register_flush ("write_blueflood", wb_flush, &user_data);

        user_data.free_func = wb_callback_free;
        plugin_register_write ("write_blueflood", wb_write, &user_data);
        INFO ("blueflood write callback registered");

        return (0);
} /* }}} int wb_config_url */

static int wb_config (oconfig_item_t *ci) /* {{{ */
{
        int i;

        for (i = 0; i < ci->children_num; i++)
        {
                oconfig_item_t *child = ci->children + i;

                if (strcasecmp ("URL", child->key) == 0)
                        wb_config_url (child);
                else
                {
                        ERROR ("write_blueflood plugin: Invalid configuration "
                                        "option: %s.", child->key);
                }
        }

        return (0);
} /* }}} int wb_config */

static int wb_init (void) /* {{{ */
{
        /* Call this while collectd is still single-threaded to avoid
         * initialization issues in libgcrypt. */
        INFO ("write_blueflood init");
        curl_global_init (CURL_GLOBAL_SSL);
        INFO ("write_blueflood_init_successful");
        return (0);
} /* }}} int wb_init */

void module_register (void) /* {{{ */
{       
        INFO ("write_blueflood registered");
        plugin_register_complex_config ("write_blueflood", wb_config);
        plugin_register_init ("write_blueflood", wb_init);
} /* }}} void module_register */

/* vim: set fdm=marker sw=8 ts=8 tw=78 et : */
