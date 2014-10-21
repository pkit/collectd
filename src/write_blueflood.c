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
        char *credentials;
        _Bool verify_peer;
        _Bool verify_host;
        char *cacert;
        char *capath;
        char *clientkey;
        char *clientcert;
        char *clientkeypass;
        long sslversion;

        _Bool store_rates;

#define WH_FORMAT_COMMAND 0
#define WH_FORMAT_JSON    1
        int format;

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

static void wb_reset_buffer (wb_callback_t *cb)  /* {{{ */
{
        memset (cb->send_buffer, 0, cb->send_buffer_size);
        cb->send_buffer_free = cb->send_buffer_size;
        cb->send_buffer_fill = 0;
        cb->send_buffer_init_time = cdtime ();

        if (cb->format == WH_FORMAT_JSON)
        {
                format_json_initialize (cb->send_buffer,
                                &cb->send_buffer_fill,
                                &cb->send_buffer_free);
        }
} /* }}} wb_reset_buffer */

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
        if (cb->format == WH_FORMAT_JSON)
                headers = curl_slist_append (headers, "Content-Type: application/json");
        else
                headers = curl_slist_append (headers, "Content-Type: text/plain");
        headers = curl_slist_append (headers, "Expect:");
        curl_easy_setopt (cb->curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt (cb->curl, CURLOPT_ERRORBUFFER, cb->curl_errbuf);
        curl_easy_setopt (cb->curl, CURLOPT_URL, cb->location);

        if (cb->user != NULL)
        {
                size_t credentials_size;

                credentials_size = strlen (cb->user) + 2;
                if (cb->pass != NULL)
                        credentials_size += strlen (cb->pass);

                cb->credentials = (char *) malloc (credentials_size);
                if (cb->credentials == NULL)
                {
                        ERROR ("curl plugin: malloc failed.");
                        return (-1);
                }

                ssnprintf (cb->credentials, credentials_size, "%s:%s",
                                cb->user, (cb->pass == NULL) ? "" : cb->pass);
                curl_easy_setopt (cb->curl, CURLOPT_USERPWD, cb->credentials);
                curl_easy_setopt (cb->curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
        }

        curl_easy_setopt (cb->curl, CURLOPT_SSL_VERIFYPEER, (long) cb->verify_peer);
        curl_easy_setopt (cb->curl, CURLOPT_SSL_VERIFYHOST,
                        cb->verify_host ? 2L : 0L);
        curl_easy_setopt (cb->curl, CURLOPT_SSLVERSION, cb->sslversion);
        if (cb->cacert != NULL)
                curl_easy_setopt (cb->curl, CURLOPT_CAINFO, cb->cacert);
        if (cb->capath != NULL)
                curl_easy_setopt (cb->curl, CURLOPT_CAPATH, cb->capath);

        if (cb->clientkey != NULL && cb->clientcert != NULL)
        {
            curl_easy_setopt (cb->curl, CURLOPT_SSLKEY, cb->clientkey);
            curl_easy_setopt (cb->curl, CURLOPT_SSLCERT, cb->clientcert);

            if (cb->clientkeypass != NULL)
                curl_easy_setopt (cb->curl, CURLOPT_SSLKEYPASSWD, cb->clientkeypass);
        }

        wb_reset_buffer (cb);

        return (0);
} /* }}} int wb_callback_init */

static int wb_flush_nolock (cdtime_t timeout, wb_callback_t *cb) /* {{{ */
{
        int status;

        DEBUG ("write_blueflood plugin: wh_flush_nolock: timeout = %.3f; "
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

        if (cb->format == WH_FORMAT_COMMAND)
        {
                if (cb->send_buffer_fill <= 0)
                {
                        cb->send_buffer_init_time = cdtime ();
                        return (0);
                }

                status = wb_send_buffer (cb);
                wb_reset_buffer (cb);
        }
        else if (cb->format == WH_FORMAT_JSON)
        {
                if (cb->send_buffer_fill <= 2)
                {
                        cb->send_buffer_init_time = cdtime ();
                        return (0);
                }

                status = format_json_finalize (cb->send_buffer,
                                &cb->send_buffer_fill,
                                &cb->send_buffer_free);
                if (status != 0)
                {
                        ERROR ("write_blueflood: wh_flush_nolock: "
                                        "format_json_finalize failed.");
                        wb_reset_buffer (cb);
                        return (status);
                }

                status = wb_send_buffer (cb);
                wb_reset_buffer (cb);
        }
        else
        {
                ERROR ("write_blueflood: wh_flush_nolock: "
                                "Unknown format: %i",
                                cb->format);
                return (-1);
        }

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
                        ERROR ("write_blueflood plugin: wh_callback_init failed.");
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
        sfree (cb->user);
        sfree (cb->pass);
        sfree (cb->credentials);
        sfree (cb->cacert);
        sfree (cb->capath);
        sfree (cb->clientkey);
        sfree (cb->clientcert);
        sfree (cb->clientkeypass);
        sfree (cb->send_buffer);

        sfree (cb);
} /* }}} void wb_callback_free */

static int wb_write_command (const data_set_t *ds, const value_list_t *vl, /* {{{ */
                wb_callback_t *cb)
{
        char key[10*DATA_MAX_NAME_LEN];
        char values[512];
        char command[1024];
        size_t command_len;

        int status;

        if (0 != strcmp (ds->type, vl->type)) {
                ERROR ("write_blueflood plugin: DS type does not match "
                                "value list type");
                return -1;
        }

        /* Copy the identifier to `key' and escape it. */
        status = FORMAT_VL (key, sizeof (key), vl);
        if (status != 0) {
                ERROR ("write_blueflood plugin: error with format_name");
                return (status);
        }
        escape_string (key, sizeof (key));

        /* Convert the values to an ASCII representation and put that into
         * `values'. */
        status = format_values (values, sizeof (values), ds, vl, cb->store_rates);
        if (status != 0) {
                ERROR ("write_blueflood plugin: error with "
                                "wh_value_list_to_string");
                return (status);
        }

        command_len = (size_t) ssnprintf (command, sizeof (command),
                        "PUTVAL %s interval=%.3f %s\r\n",
                        key,
                        CDTIME_T_TO_DOUBLE (vl->interval),
                        values);
        if (command_len >= sizeof (command)) {
                ERROR ("write_blueflood plugin: Command buffer too small: "
                                "Need %zu bytes.", command_len + 1);
                return (-1);
        }

        pthread_mutex_lock (&cb->send_lock);

        if (cb->curl == NULL)
        {
                status = wb_callback_init (cb);
                if (status != 0)
                {
                        ERROR ("write_blueflood plugin: wh_callback_init failed.");
                        pthread_mutex_unlock (&cb->send_lock);
                        return (-1);
                }
        }

        if (command_len >= cb->send_buffer_free)
        {
                status = wb_flush_nolock (/* timeout = */ 0, cb);
                if (status != 0)
                {
                        pthread_mutex_unlock (&cb->send_lock);
                        return (status);
                }
        }
        assert (command_len < cb->send_buffer_free);

        /* `command_len + 1' because `command_len' does not include the
         * trailing null byte. Neither does `send_buffer_fill'. */
        memcpy (cb->send_buffer + cb->send_buffer_fill,
                        command, command_len + 1);
        cb->send_buffer_fill += command_len;
        cb->send_buffer_free -= command_len;

        DEBUG ("write_blueflood plugin: <%s> buffer %zu/%zu (%g%%) \"%s\"",
                        cb->location,
                        cb->send_buffer_fill, cb->send_buffer_size,
                        100.0 * ((double) cb->send_buffer_fill) / ((double) cb->send_buffer_size),
                        command);

        /* Check if we have enough space for this command. */
        pthread_mutex_unlock (&cb->send_lock);

        return (0);
} /* }}} int wb_write_command */

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
                        ERROR ("write_blueflood plugin: wh_callback_init failed.");
                        pthread_mutex_unlock (&cb->send_lock);
                        return (-1);
                }
        }

        format_status = format_json_value_list (cb->send_buffer,
                        &cb->send_buffer_fill,
                        &cb->send_buffer_free,
                        ds, vl, cb->store_rates);

        if (format_status == (-ENOMEM))
        {
                // this is now a real error condition, not a sign that we need
                // to flush.

                //TODO: ERROR!

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

        if (cb->format == WH_FORMAT_JSON)
                status = wb_write_json (ds, vl, cb);
        else
                status = wb_write_command (ds, vl, cb);

        return (status);
} /* }}} int wb_write */

static int config_set_format (wb_callback_t *cb, /* {{{ */
                oconfig_item_t *ci)
{
        char *string;

        if ((ci->values_num != 1)
                        || (ci->values[0].type != OCONFIG_TYPE_STRING))
        {
                WARNING ("write_blueflood plugin: The `%s' config option "
                                "needs exactly one string argument.", ci->key);
                return (-1);
        }

        string = ci->values[0].value.string;
        if (strcasecmp ("Command", string) == 0)
                cb->format = WH_FORMAT_COMMAND;
        else if (strcasecmp ("JSON", string) == 0)
                cb->format = WH_FORMAT_JSON;
        else
        {
                ERROR ("write_blueflood plugin: Invalid format string: %s",
                                string);
                return (-1);
        }

        return (0);
} /* }}} int config_set_format */

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
        cb->verify_peer = 1;
        cb->verify_host = 1;
        cb->format = WH_FORMAT_COMMAND;
        cb->sslversion = CURL_SSLVERSION_DEFAULT;

        pthread_mutex_init (&cb->send_lock, /* attr = */ NULL);

        cf_util_get_string (ci, &cb->location);
        if (cb->location == NULL)
                return (-1);

        for (i = 0; i < ci->children_num; i++)
        {
                oconfig_item_t *child = ci->children + i;

                if (strcasecmp ("User", child->key) == 0)
                        cf_util_get_string (child, &cb->user);
                else if (strcasecmp ("Password", child->key) == 0)
                        cf_util_get_string (child, &cb->pass);
                else if (strcasecmp ("VerifyPeer", child->key) == 0)
                        cf_util_get_boolean (child, &cb->verify_peer);
                else if (strcasecmp ("VerifyHost", child->key) == 0)
                        cf_util_get_boolean (child, &cb->verify_host);
                else if (strcasecmp ("CACert", child->key) == 0)
                        cf_util_get_string (child, &cb->cacert);
                else if (strcasecmp ("CAPath", child->key) == 0)
                        cf_util_get_string (child, &cb->capath);
                else if (strcasecmp ("ClientKey", child->key) == 0)
                        cf_util_get_string (child, &cb->clientkey);
                else if (strcasecmp ("ClientCert", child->key) == 0)
                        cf_util_get_string (child, &cb->clientcert);
                else if (strcasecmp ("ClientKeyPass", child->key) == 0)
                        cf_util_get_string (child, &cb->clientkeypass);
                else if (strcasecmp ("SSLVersion", child->key) == 0)
                {
                        char *value = NULL;

                        cf_util_get_string (child, &value);

                        if (value == NULL || strcasecmp ("default", value) == 0)
                                cb->sslversion = CURL_SSLVERSION_DEFAULT;
                        else if (strcasecmp ("SSLv2", value) == 0)
                                cb->sslversion = CURL_SSLVERSION_SSLv2;
                        else if (strcasecmp ("SSLv3", value) == 0)
                                cb->sslversion = CURL_SSLVERSION_SSLv3;
                        else if (strcasecmp ("TLSv1", value) == 0)
                                cb->sslversion = CURL_SSLVERSION_TLSv1;
#if (LIBCURL_VERSION_MAJOR > 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 34)
                        else if (strcasecmp ("TLSv1_0", value) == 0)
                                cb->sslversion = CURL_SSLVERSION_TLSv1_0;
                        else if (strcasecmp ("TLSv1_1", value) == 0)
                                cb->sslversion = CURL_SSLVERSION_TLSv1_1;
                        else if (strcasecmp ("TLSv1_2", value) == 0)
                                cb->sslversion = CURL_SSLVERSION_TLSv1_2;
#endif
                        else
                                ERROR ("write_blueflood plugin: Invalid SSLVersion "
                                                "option: %s.", value);

                        sfree(value);
                }
                else if (strcasecmp ("Format", child->key) == 0)
                        config_set_format (cb, child);
                else if (strcasecmp ("StoreRates", child->key) == 0)
                        cf_util_get_boolean (child, &cb->store_rates);
                else if (strcasecmp ("BufferSize", child->key) == 0)
                        cf_util_get_int (child, &buffer_size);
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
