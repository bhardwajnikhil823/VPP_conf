/*
 * node.c - filter_plugin node for tracing incoming ICMP packets.
 *
 * This node is inserted into the ip4-unicast arc so that it can inspect IPv4 packets.
 * When an IPv4 packet is received and its protocol is ICMP, it logs the total IP length.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp.h>
#include <vlib/unix/plugin.h>
#include <filter_plugin/filter_plugin.h>

/* Trace structure for our node */
typedef struct {
  u32 sw_if_index;
  u32 next_index;
  ip4_address_t src;
  ip4_address_t dst;
  u8 protocol;
  u16 src_port;
  u32 seq_number;
  u16 dst_port;
  u8 function_code;
  u16 trans_id;
} filter_plugin_trace_t;


typedef struct {
  u16 trans_id;
  u16 protocol;
  u16 len;
  u8 unit_id;
} modtcp_trace_t;

typedef struct {
  modtcp_trace_t modtcp;
  u8 function_code;
} modbus_trace_t;


/* Packet trace format function */
static u8 * format_filter_plugin_trace (u8 * s, va_list * args) {
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  filter_plugin_trace_t * t = va_arg (*args, filter_plugin_trace_t *);
  if(t->src_port !=0){
  s = format (s, "FILTER_PLUGIN Trace:\n");
  s = format (s, "FILTER_PLUGIN: sw_if_index %d, next index %d, Src IP: %U, Dst IP: %U, Protocol: %d, SRC Port: %d, Seq_Num: %u, Dest Port: %d, funtion code: %d, trans id: %d",
              t->sw_if_index, t->next_index,
              format_ip4_address, &t->src,
              format_ip4_address, &t->dst, t->protocol,t->src_port, t->seq_number, t->dst_port, t->function_code, t->trans_id);
  }
  return s;
}

/* We define only one “next” (drop) for simplicity */
typedef enum {
  FILTER_PLUGIN_NEXT_DROP,
  FILTER_PLUGIN_NEXT_FORWARD,
  FILTER_PLUGIN_N_NEXT,
} filter_plugin_next_t;

/* Main processing function. For each packet, if the packet is IPv4 and its protocol is ICMP,
   log the IP total length using vlib_log_debug(0, …). */
always_inline uword filter_plugin_inline (vlib_main_t * vm,
                                          vlib_node_runtime_t * node,
                                          vlib_frame_t * frame,
                                          int is_trace) {
  u32 n_left_from, * from;
  vlib_buffer_t * bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0) {
    next[0] = FILTER_PLUGIN_NEXT_FORWARD; // default to drop (or forward as appropriate)
    if (b[0]->current_length >= sizeof(ip4_header_t)) {
      ip4_header_t * ip = (ip4_header_t *) vlib_buffer_get_current(b[0]);
      if (((ip->ip_version_and_header_length >> 4) == 4) &&
          (ip->protocol == IP_PROTOCOL_ICMP)) {
        u16 icmp_len = clib_net_to_host_u16(ip->length);
        vlib_log_debug(0, "ICMP packet received, length: %u bytes", icmp_len);
      }
    }
    if (is_trace && (b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
      filter_plugin_trace_t * t = vlib_add_trace(vm, node, b[0], sizeof(*t));
      ethernet_header_t * eh = (ethernet_header_t *) vlib_buffer_get_current(b[0]);
      ip4_header_t * ip = (ip4_header_t *) (eh + 1);
      t->next_index = next[0];
      t->sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
      t->src = ip->src_address;
      t->dst = ip->dst_address;
      t->protocol = ip->protocol;
      if(t->protocol == 6){
       // t->protocol=2;
        u32 ip_header_length = (ip->ip_version_and_header_length & 0x0F) * 4;
        tcp_header_t *tcp = (tcp_header_t *)((u8 *)ip + ip_header_length);
        t->src_port = clib_net_to_host_u16(tcp->src_port);
        t->seq_number = clib_net_to_host_u32(tcp->seq_number);
        t->dst_port = clib_net_to_host_u16(tcp->dst_port);
        //u32 tcp_header_length = ((tcp->data_offset_and_reserved >> 4) & 0x0F) * 4;
        u16* trans_id = (u16*)(tcp+1);
        t->trans_id=(*trans_id);
        // Extract the TCP header length (in bytes).
        u32 tcp_header_length = ((tcp->data_offset_and_reserved >> 4) & 0x0F) * 4;

        // Locate the Modbus data that immediately follows the TCP header.
        modbus_trace_t *modbus = (modbus_trace_t *)((u8 *)tcp + tcp_header_length);

        // Extract the Modbus function code.
        t->function_code = modbus->function_code;
      }
    }
    b++;
    next++;
    n_left_from--;
  }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

/* Node function */
VLIB_NODE_FN (filter_plugin_node) (vlib_main_t * vm,
                                     vlib_node_runtime_t * node,
                                     vlib_frame_t * frame) {
  int trace_enabled = (node->flags & VLIB_NODE_FLAG_TRACE) ? 1 : 0;
  return filter_plugin_inline(vm, node, frame, trace_enabled);
}


VLIB_REGISTER_NODE (filter_plugin_node) = {
  .name = "filter_plugin",
  .flags = VLIB_NODE_FLAG_IS_OUTPUT,
  .vector_size = sizeof(u32),
  .format_trace = format_filter_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = FILTER_PLUGIN_N_NEXT,
  .next_nodes = {
    [FILTER_PLUGIN_NEXT_FORWARD] = "ethernet-input",
    [FILTER_PLUGIN_NEXT_DROP] = "error-drop",
  },
};

// #endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
