/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package logs

import (
	"github.com/spf13/cobra"
)

func NewRouterLogsCmd() *cobra.Command {
	parseRouterLogs := &ParseRouterLogs{}
	parseRouterLogs.Init()

	parseRouterLogsCmd := &cobra.Command{
		Use:   "router",
		Short: "Parse router logs",
		Args:  cobra.ExactArgs(1),
		RunE:  parseRouterLogs.run,
	}

	parseRouterLogs.addCommonArgs(parseRouterLogsCmd)

	showRouterLogCategoriesCmd := &cobra.Command{
		Use:   "categories",
		Short: "Show router log entry categories",
		Run:   parseRouterLogs.ShowCategories,
	}

	parseRouterLogsCmd.AddCommand(showRouterLogCategoriesCmd)
	return parseRouterLogsCmd
}

type ParseRouterLogs struct {
	JsonLogsParser
}

func (self *ParseRouterLogs) Init() {
	self.filters = getRouterLogFilters()
}

func getRouterLogFilters() []LogFilter {
	var result []LogFilter

	// idle scanner/forward fault notifier
	result = append(result,
		&filter{
			id:   "IDLE_CIRCUIT_FOUND",
			desc: "a circuit has been idle for at least one minute and the controller will be checked to see if the circuit is still valid",
			LogMatcher: AndMatchers(
				FieldContains("file", "forwarder/scanner.go"),
				FieldContains("msg", " idle after "),
			)},
		&filter{
			id:   "IDLE_CONF_SENT",
			desc: "controller has been notified of idle circuits and can respond if they are no longer valid",
			LogMatcher: AndMatchers(
				FieldContains("msg", "sent confirmation for "),
				FieldContains("file", "forwarder/scanner.go"),
			)},
		&filter{
			id:   "FORWARD_FAULTS_REPORTED",
			desc: "the forwarding fault notifier has reported forwarding faults to the controller",
			LogMatcher: AndMatchers(
				FieldContains("file", "forwarder/faulter.go"),
				FieldMatches("msg", "reported.*forwarding faults"),
			)},
	)

	// misc
	result = append(result,
		&filter{
			id:   "ROUTE_DEST_EXISTS",
			desc: "attempting to establish a circuit, but a previous dial attempt already established the egress connection",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "destination exists for "),
				FieldContains("file", "handler_ctrl/route.go"),
			)})

	// xgress related log messges
	result = append(result,
		&filter{
			id:   "XG_READ_ERR",
			desc: "read failure on the client or server side of the circuit; will cause the circuit to be torn down",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "read failed"),
				FieldContains("file", "xgress/xgress.go"),
			)},
		&filter{
			id:   "XG_WRITE_ERR",
			desc: "write failure on the client or server side of the circuit; will cause the circuit to be torn down",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "write failed"),
				FieldContains("file", "xgress/xgress.go"),
			)},
		&filter{
			id:   "XG_PAYLOAD_BUFFER_ERR",
			desc: "while a circuit was being closed, data was received from the client or server",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "failure to buffer payload"),
				FieldEquals("error", "payload buffer closed"),
				FieldContains("file", "xgress/xgress.go"),
			)},
		&filter{
			id:   "XG_ACK_BUFFER_ERR",
			desc: "while a circuit was being closed, an ack was received",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "payload buffer closed"),
				FieldContains("file", "xgress/link_send_buffer.go"),
			)},
		&filter{
			id:   "XG_FWD_ERR",
			desc: "router can't forward a message most likely because the circuit is in the middle of being torn down",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "unable to forward"),
				FieldContains("file", "handler_xgress/receive.go"),
			)},
		&filter{
			id:   "XG_RTX_ERR_NO_DEST",
			desc: "retransmission failed because the circuit has been torn down since the payload was originally sent",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "unexpected error while retransmitting payload"),
				FieldStartsWith("error", "cannot forward payload, no destination for "),
				FieldContains("file", "xgress/retransmitter.go"),
			)},
		&filter{
			id:   "XG_RTX_ERR_NO_FWD_TABLE",
			desc: "retransmission failed because the circuit has no forwarding table",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "unexpected error while retransmitting payload"),
				FieldStartsWith("error", "cannot forward payload, no forward table"),
				FieldContains("file", "xgress/retransmitter.go"),
			)},
		&filter{
			id:   "XG_START_TIMEOUT",
			desc: "the terminator side of the xgress was torn down because the start signal wasn't received in time from the initiator",
			LogMatcher: AndMatchers(
				FieldMatches("msg", "xgress.*not started in time, closing"),
				FieldContains("file", "xgress/xgress.go"),
			)},
		&filter{
			id:   "XG_TRANSPORT_DIAL_OK",
			desc: "a router terminated service has made a successful connection to a server hosting an application",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "successful connection "),
				FieldContains("file", "xgress_transport/dialer.go"),
			)},
	)

	// channel messages
	result = append(result,
		&filter{
			id:   "CHANNEL_TLS_ERR_NO_CERT",
			desc: "a connection attempt was made to a channel TLS listener but no certificate was provided",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "error receiving hello from "),
				FieldContains("msg", "tls: client didn't provide a certificate"),
				FieldContains("file", "channel2/classic_listener.go"),
			)},
		&filter{
			id:   "CHANNEL_TLS_ERR_TIMEOUT",
			desc: "a connection attempt was made to a TLS listener but it timed out",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "error receiving hello from [tls:"),
				FieldContains("msg", "i/o timeout"),
				FieldContains("file", "channel2/classic_listener.go"),
			)},
		&filter{
			id:   "CHANNEL_LATENCY_TIMEOUT",
			desc: "a latency ping was sent, but no response was received within the timeout",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "latency timeout after "),
				FieldContains("file", "metrics/latency.go"),
			)},
		&filter{
			id:   "CHANNEL_READ_ERR_PEER_RESET",
			desc: "channel read failed because the connection was reset by its peer",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "rx error"),
				FieldContains("msg", "connection reset by peer"),
				FieldContains("file", "channel2/impl.go"),
			)},
		&filter{
			id:   "CHANNEL_READ_ERR_TIMEOUT",
			desc: "channel read failed because the connection timed out",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "rx error"),
				FieldContains("msg", "read: connection timed out"),
				FieldContains("file", "channel2/impl.go"),
			)})

	// transport messages
	result = append(result,
		&filter{
			id:   "CHANNEL_TCP_ACCEPTED",
			desc: "a tcp connection has been accepted",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "accepted connection"),
				FieldContains("file", "transport/tcp/listener.go"),
			)},
	)

	// link messages
	result = append(result,
		&filter{
			id:   "LINK_DIAL_SPLIT",
			desc: "a link is being dialed to another router with separate connections for data and acknowledgements",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "dialing link with split payload/ack channels"),
				FieldContains("file", "xlink_transport/dialer.go"),
			)},
		&filter{
			id:   "LINK_DIAL_REQUESTED",
			desc: "received a request from the controller to dial another router",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "received link connect request"),
				FieldContains("file", "handler_ctrl/dial.go"),
			)},
		&filter{
			id:   "LINK_DIAL",
			desc: "dialing another router to establish a link",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "dialing link"),
				FieldContains("file", "handler_ctrl/dial.go"),
			)},
		&filter{
			id:   "LINK_ESTABLISHED",
			desc: "a link to another router has been established",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "link established"),
				FieldContains("file", "handler_ctrl/dial.go"),
			)},
		&filter{
			id:   "LINK_DIAL_PAYLOAD",
			desc: "dialing the link payload channel of a link",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "dialing payload channel for"),
				FieldContains("file", "xlink_transport/dialer.go"),
			)},
		&filter{
			id:   "LINK_DIAL_ACK",
			desc: "dialing the link ack channel of a link",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "dialing ack channel for"),
				FieldContains("file", "xlink_transport/dialer.go"),
			)},
		&filter{
			id:   "LINK_CLOSED",
			desc: "a router to router link was closed",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "link closed"),
				FieldContains("file", "handler_link/close.go"),
			)},
		&filter{
			id:   "LINK_FAULT_SENT",
			desc: "the router notified the controller that a link failed",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "transmitted link fault"),
				FieldContains("file", "handler_link/close.go"),
			)},
		&filter{
			id:   "LINK_ACCEPTED",
			desc: "another router has dialed this router and a link connection has made. If using split links, this only one of two connections",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "accepting link"),
				FieldContains("file", "xlink_transport/listener.go"),
			)},
		&filter{
			id:   "LINK_SPLIT_ACCEPT_FIRST",
			desc: "another router has dialed this router and the first link connection of a split link has been made. Split links have separate conns for payloads and acks",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "accepted 1 part of split conn"),
				FieldContains("file", "xlink_transport/listener.go"),
			)},
		&filter{
			id:   "LINK_SPLIT_ACCEPT_SECOND",
			desc: "another router has dialed this router and the second link connection of a split link has been made. Split links have separate conns for payloads and acks",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "accepted 2 part of split conn"),
				FieldContains("file", "xlink_transport/listener.go"),
			)},
		// make two of following 3 into debug messages
		&filter{
			id:   "LINK_SPLIT_ACCEPTED",
			desc: "another router has dialed this router and both link connections of a split link has made. Split links have separate conns for payloads and acks",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "accepting split link"),
				FieldContains("file", "xlink_transport/listener.go"),
			)},
		&filter{
			id:   "LINK_ACCEPTED1",
			desc: "another router has dialed this router and the link is being accepted",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "accepted link"),
				FieldContains("file", "xlink_transport/listener.go"),
			)},
		&filter{
			id:   "LINK_ACCEPTED2",
			desc: "another router has dialed this router and a link has been established",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "accepted new link"),
				FieldContains("file", "router/accepter.go"),
			)},
	)

	// control channel
	result = append(result,
		&filter{
			id:   "CTRL_CH_RECONNECT_START",
			desc: "the router to controller control channel connection died and the router trying to reconnect",
			LogMatcher: AndMatchers(
				FieldContains("msg", "starting reconnection process"),
				FieldContains("file", "channel2/reconnecting_impl.go"),
			)},
		&filter{
			id:   "CTRL_CH_RECONNECT_ERR",
			desc: "the router attempted to reconnect the control channel and failed",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/reconnecting_dialer.go"),
				FieldMatches("msg", "reconnection attempt.*failed"),
			)},
		&filter{
			id:   "CTRL_CH_RECONNECT_OK",
			desc: "the router attempted to reconnect the control channel and succeeded",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "reconnected"),
				FieldContains("file", "channel2/reconnecting_impl.go"),
			)},
		&filter{
			id:   "CTRL_CH_RECONNECT_PING",
			desc: "the router is checking the control channel to see if it needs to be reconnected",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/reconnecting_impl.go"),
				FieldContains("func", "pingInstance"),
			)},
		&filter{
			id:   "CTRL_CH_RECONNECT_PING_ERR",
			desc: "the router control channel ping failed",
			LogMatcher: AndMatchers(
				FieldContains("msg", "unable to ping"),
				FieldContains("file", "channel2/reconnecting_dialer.go"),
			)},
		&filter{
			id:   "CTRL_CH_EDGE_HELLO",
			desc: "the controller sent us a hello message after a control channel was established or reconnected",
			LogMatcher: AndMatchers(
				FieldContains("msg", "received server hello"),
				FieldContains("file", "handler_edge_ctrl/hello.go"),
			)},
	)

	// session sync
	result = append(result,
		&filter{
			id:   "API_SESSION_SYNC_START",
			desc: "The controller has started a full api session sync",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_edge_ctrl/apiSessionAdded.go"),
				FieldMatches("msg", "api session.*starting"),
			)},
		&filter{
			id:   "API_SESSION_SYNC_CHUNK",
			desc: "The controller sent a chunk of api session data",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_edge_ctrl/apiSessionAdded.go"),
				FieldStartsWith("msg", "received api session sync chunk"),
			)},
		&filter{
			id:   "API_SESSION_SYNC_DONE",
			desc: "The controller has finished a full api session sync",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_edge_ctrl/apiSessionAdded.go"),
				FieldStartsWith("msg", "finished sychronizing api sessions"),
			)},
	)

	// tunneler messages
	result = append(result,
		&filter{
			id:   "TUNNEL_DIAL_SUCCESS",
			desc: "a router embedded tunneler has made a successful connection to a server hosting an application",
			LogMatcher: AndMatchers(
				FieldStartsWith("msg", "successful connection "),
				FieldContains("file", "xgress_edge_tunnel/dialer.go"),
			)},
		&filter{
			id:   "TUNNEL_TPROXY_TCP_ACCEPT",
			desc: "tproxy based tunneler has accepted a TCP connection",
			LogMatcher: AndMatchers(
				FieldContains("file", "tproxy/tproxy_linux.go"),
				FieldStartsWith("msg", "received connection"),
			)},
		&filter{
			id:   "TUNNEL_DIAL_ERR",
			desc: "a router embedded tunneler failed to create a circuit",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "failed to dial fabric"),
				FieldContains("file", "xgress_edge_tunnel/fabric.go"),
			)},
		&filter{
			id:   "TUNNEL_DIAL_ERR_TIMEOUT",
			desc: "a router embedded tunneler failed to create a circuit because the request timed out",
			LogMatcher: AndMatchers(
				FieldEquals("msg", "tunnel failed"),
				FieldStartsWith("error", "timed out after"),
				FieldContains("file", "tunnel/tunnel.go"),
			)})

	return result
}

func (self *ParseRouterLogs) run(cmd *cobra.Command, args []string) error {
	if err := self.validate(); err != nil {
		return err
	}

	ctx := &JsonParseContext{
		ParseContext: ParseContext{
			path: args[0],
		},
	}
	return ScanJsonLines(ctx, self.summarizeLogEntry)
}
