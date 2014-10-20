/**
 * collectd - src/utils_format_json.c
 * Copyright (C) 2009       Florian octo Forster
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 **/

#include "collectd.h"
#include "plugin.h"
#include "common.h"

#include "utils_cache.h"
#include "utils_format_json.h"

static int json_escape_string (char *buffer, size_t buffer_size, /* {{{ */
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
  dst_pos++; \
} while (0)

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
} /* }}} int json_escape_string */

static int value_list_to_json (char *buffer, size_t buffer_size, /* {{{ */
                const data_set_t *ds, const value_list_t *vl, int store_rates)
{
  size_t offset = 0;
  int status;
  int store[3][10];
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
    offset += ((size_t) status); \
} while (0)

#define BUFFER_ADD_KEYVAL(key, value) do { \
  int status2; \
  status2 = json_escape_string (buffer, sizeof (buffer), (value)); \
  if (status2 != 0) \
    return (status2); \
  BUFFER_ADD (",\"%s\":%s", (key), buffer); \
} while (0)

  /* All value lists have a leading comma. The first one will be replaced with
   * a square bracket in `format_json_finalize'. */
  BUFFER_ADD (",{");
  for (i = 0; i < ds->ds_num; i++)
  {
    if (ds->ds[i].type == DS_TYPE_GAUGE)
    {
      INFO ("write_blueflood plugin found gauge");
      store[0][gauge_offset] = i;
      gauge_offset++;
    }
    /*TODO : Figure out what is happening with this block of code
    else if (store_rates)
    {
      if (rates == NULL)
        rates = uc_get_rate (ds, vl);
      if (rates == NULL)
      {
        WARNING ("utils_format_json: uc_get_rate failed.");
        sfree(rates);
        return (-1);
      }

      if(isfinite (rates[i]))
        BUFFER_ADD ("%g", rates[i]);
      else
        BUFFER_ADD ("null");
    }*/
    else if (ds->ds[i].type == DS_TYPE_COUNTER) {
      INFO ("write_blueflood plugin found counter");
      store[1][counter_offset] = i;
      counter_offset++;
    }
    else if (ds->ds[i].type == DS_TYPE_DERIVE) {
      DEBUG ("Skipping derive data type for now");
    }
    else if (ds->ds[i].type == DS_TYPE_ABSOLUTE) {
      INFO ("write_blueflood plugin found absolute");
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
  
  if (counter_offset > 0) {
    BUFFER_ADD ("\"counters\":[");
    for (i = 0; i < counter_offset; i++) {
      INFO ("ADDING COUNTER to buffer");
      BUFFER_ADD ("{");
      BUFFER_ADD_KEYVAL ("\"name\":", vl->plugin);
      BUFFER_ADD ("\"value\":");
      BUFFER_ADD ("%llu", vl->values[store[1][i]].counter);
      BUFFER_ADD ("},");
    }
    BUFFER_ADD ("]");
  }
  
  if (gauge_offset > 0) {
    BUFFER_ADD (",\"gauges\":[");
    for (i = 0; i < gauge_offset; i++) {
      INFO ("ADDING GAUGE TO BUFFER");
      INFO ("ADDED metric name as %s, metric value as %g", vl->plugin, vl->values[store[0][i]].gauge);
      BUFFER_ADD ("{");
      BUFFER_ADD_KEYVAL ("\"name\":", vl->plugin);
      BUFFER_ADD ("\"value\":");
      if(isfinite (vl->values[store[0][i]].gauge)) {
        BUFFER_ADD ("%g", vl->values[store[0][i]].gauge);
      }
      else
        BUFFER_ADD ("null");
      BUFFER_ADD ("},");
    }
    BUFFER_ADD ("]");
  }

  if (absolute_offset > 0) {
    BUFFER_ADD (",\"gauges\":[");
    for (i = 0; i < absolute_offset; i++) {
      INFO ("ADDING ABSOLUTE tO BUFFER");
      BUFFER_ADD ("{");
      BUFFER_ADD_KEYVAL ("\"name\":", vl->plugin);
      BUFFER_ADD ("\"value\":");
      BUFFER_ADD ("%"PRIu64, vl->values[store[2][i]].absolute); 
      BUFFER_ADD ("},");
    }
    BUFFER_ADD ("]");
  }

  BUFFER_ADD (",\"timestamp\":%lu", CDTIME_T_TO_MS (vl->time));
  BUFFER_ADD (",\"flushInterval\":%lu", CDTIME_T_TO_MS (vl->interval));
  BUFFER_ADD ("}");

#undef BUFFER_ADD
#undef BUFFER_ADD_KEYVAL

  DEBUG ("format_json: value_list_to_json: buffer = %s;", buffer);

  return (0);
} /* }}} int value_list_to_json */

static int format_json_value_list_nocheck (char *buffer, /* {{{ */
    size_t *ret_buffer_fill, size_t *ret_buffer_free,
    const data_set_t *ds, const value_list_t *vl,
    int store_rates, size_t temp_size)
{
  char temp[temp_size];
  int status;

  status = value_list_to_json (temp, sizeof (temp), ds, vl, store_rates);
  if (status != 0)
    return (status);
  temp_size = strlen (temp);

  memcpy (buffer + (*ret_buffer_fill), temp, temp_size + 1);
  (*ret_buffer_fill) += temp_size;
  (*ret_buffer_free) -= temp_size;

  return (0);
} /* }}} int format_json_value_list_nocheck */

int format_json_initialize (char *buffer, /* {{{ */
    size_t *ret_buffer_fill, size_t *ret_buffer_free)
{
  size_t buffer_fill;
  size_t buffer_free;

  if ((buffer == NULL) || (ret_buffer_fill == NULL) || (ret_buffer_free == NULL))
    return (-EINVAL);

  buffer_fill = *ret_buffer_fill;
  buffer_free = *ret_buffer_free;

  buffer_free = buffer_fill + buffer_free;
  buffer_fill = 0;

  if (buffer_free < 3)
    return (-ENOMEM);

  memset (buffer, 0, buffer_free);
  *ret_buffer_fill = buffer_fill;
  *ret_buffer_free = buffer_free;

  return (0);
} /* }}} int format_json_initialize */

int format_json_finalize (char *buffer, /* {{{ */
    size_t *ret_buffer_fill, size_t *ret_buffer_free)
{
  size_t pos;

  if ((buffer == NULL) || (ret_buffer_fill == NULL) || (ret_buffer_free == NULL))
    return (-EINVAL);

  if (*ret_buffer_free < 2)
    return (-ENOMEM);

  /* Replace the leading comma added in `value_list_to_json' with a square
   * bracket. */
  if (buffer[0] != ',')
    return (-EINVAL);
  buffer[0] = '[';

  pos = *ret_buffer_fill;
  buffer[pos] = ']';
  buffer[pos+1] = 0;

  (*ret_buffer_fill)++;
  (*ret_buffer_free)--;

  return (0);
} /* }}} int format_json_finalize */

int format_json_value_list (char *buffer, /* {{{ */
    size_t *ret_buffer_fill, size_t *ret_buffer_free,
    const data_set_t *ds, const value_list_t *vl, int store_rates)
{
  if ((buffer == NULL)
      || (ret_buffer_fill == NULL) || (ret_buffer_free == NULL)
      || (ds == NULL) || (vl == NULL))
    return (-EINVAL);

  if (*ret_buffer_free < 3)
    return (-ENOMEM);

  return (format_json_value_list_nocheck (buffer,
        ret_buffer_fill, ret_buffer_free, ds, vl,
        store_rates, (*ret_buffer_free) - 2));
} /* }}} int format_json_value_list */

/* vim: set sw=2 sts=2 et fdm=marker : */
