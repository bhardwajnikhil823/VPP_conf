/*
 * filter_plugin.c - filter plugin for tracing incoming ICMP packet lengths.
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <filter_plugin/filter_plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <filter_plugin/filter_plugin.api_enum.h>
#include <filter_plugin/filter_plugin.api_types.h>

#define REPLY_MSG_ID_BASE fmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

filter_plugin_main_t filter_plugin_main;

/* We provide a simple setup_message_id_table here so that our API messages get a unique base.
   (This is analogous to what mss_clamp does.) */
u32 setup_message_id_table(void) {
    static u32 next_message_id = 1;
    return next_message_id++;
}

/* Action function to enable/disable the plugin feature on a given interface.
   It attaches our node into the ip4-unicast arc so that ICMP packets can be observed. */
int filter_plugin_enable_disable (filter_plugin_main_t * fmp, u32 sw_if_index, int enable_disable) {
  vnet_sw_interface_t * sw;
  int rv = 0;

  if (pool_is_free_index(fmp->vnet_main->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface(fmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Attach our filter_plugin node into the ip4-unicast arc on this interface */
  vnet_feature_enable_disable("device-input", "filter_plugin", sw_if_index, enable_disable, NULL, 0);

  return rv;
}

/* CLI command function */
static clib_error_t * filter_plugin_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd) {
  filter_plugin_main_t * fmp = &filter_plugin_main;
  u32 sw_if_index = 1;
  int enable_disable = 1;
  int rv;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "disable"))
      enable_disable = 0;
    else if (unformat(input, "%U", unformat_vnet_sw_interface, fmp->vnet_main, &sw_if_index))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = filter_plugin_enable_disable(fmp, sw_if_index, enable_disable);
  if (rv)
    return clib_error_return (0, "filter_plugin_enable_disable returned %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (filter_plugin_enable_disable_command, static) = {
  .path = "filter_plugin enable-disable",
  .short_help = "filter_plugin enable-disable <interface-name> [disable]",
  .function = filter_plugin_enable_disable_command_fn,
};

/* API message handler (if needed; here commented out)
static void vl_api_filter_plugin_enable_disable_t_handler(vl_api_filter_plugin_enable_disable_t *mp) {
  vl_api_filter_plugin_enable_disable_reply_t * rmp;
  filter_plugin_main_t * fmp = &filter_plugin_main;
  int rv;
  rv = filter_plugin_enable_disable(fmp, ntohl(mp->sw_if_index), (int)(mp->enable_disable));
  REPLY_MACRO(VL_API_FILTER_PLUGIN_ENABLE_DISABLE_REPLY);
}
*/

/* Initialization function */
static clib_error_t * filter_plugin_init (vlib_main_t * vm) {
  filter_plugin_main_t * fmp = &filter_plugin_main;
  clib_error_t * error = 0;
  fmp->vlib_main = vm;
  fmp->vnet_main = vnet_get_main();
  fmp->msg_id_base = setup_message_id_table();
  return error;
}
VLIB_INIT_FUNCTION (filter_plugin_init);

VNET_FEATURE_INIT (filter_plugin, static) =
{
  .arc_name = "device-input",
  .node_name = "filter_plugin",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/* Plugin registration */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "filter_plugin: Traces incoming ICMP packet lengths",
};
