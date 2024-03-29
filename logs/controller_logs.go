/*
	Copyright NetFoundry Inc.

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

func NewCtrlLogsCommand() *cobra.Command {
	controllerLogs := &ControllerLogs{}
	controllerLogs.Init()

	controllerLogsCmd := &cobra.Command{
		Use:     "controller-logs",
		Short:   "work with Ziti controller logs",
		Args:    cobra.ExactArgs(1),
		Aliases: []string{"cl"},
	}

	filterControllerLogsCmd := &cobra.Command{
		Use:     "filter",
		Short:   "filter controller log entries",
		Aliases: []string{"f"},
		RunE:    controllerLogs.filter,
	}

	controllerLogs.addFilterArgs(filterControllerLogsCmd)

	summarizeControllerLogsCmd := &cobra.Command{
		Use:     "summarize",
		Short:   "Show controller log entry summaries",
		Aliases: []string{"s"},
		RunE:    controllerLogs.summarize,
	}

	controllerLogs.addSummarizeArgs(summarizeControllerLogsCmd)

	controllerLogs.addFilterArgs(controllerLogsCmd)

	showControllerLogCategoriesCmd := &cobra.Command{
		Use:     "categories",
		Short:   "Show controller log entry categories",
		Aliases: []string{"cat"},
		Run:     controllerLogs.ShowCategories,
	}

	controllerLogsCmd.AddCommand(filterControllerLogsCmd, summarizeControllerLogsCmd, showControllerLogCategoriesCmd)

	return controllerLogsCmd
}

type ControllerLogs struct {
	JsonLogsParser
}

func (self *ControllerLogs) Init() {
	self.filters = getControllerLogFilters()
}

func getControllerLogFilters() []LogFilter {
	var result []LogFilter

	// tls
	result = append(result,
		&filter{
			id:   "TLS_UNEXPECTED",
			desc: "received unexpected message during TLS connection negotiation",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "local error: tls: unexpected message"),
			)},
		&filter{
			id:   "TLS_TIMOUT",
			desc: "i/o timeout during tls handshake",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "i/o timeout"),
			)},
		&filter{
			id:   "TLS_EOF",
			desc: "connection closed during tls handshake",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "EOF"),
			)},
		&filter{
			id:   "TLS_PEER_RESET",
			desc: "peer reset connection during tls handshake",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "read: connection reset by peer"),
			)},
		&filter{
			id:   "TLS_UNSUPPORTED",
			desc: "client only offered unsupported TLS versions",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				OrMatchers(
					FieldContains("msg", "tls: client offered only unsupported versions"),
					FieldContains("msg", "tls: no cipher suite supported by both client and server"),
				),
			)},
		&filter{
			id:   "TLS_LEGACY",
			desc: "client used the legacy version field to negotiate TLS version",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "tls: client used the legacy version field"),
			)},
		&filter{
			id:   "TLS_BAD_CERT",
			desc: "client submitted a bad tls certificate during tls handshake",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "tls: bad certificate"),
			)},
		&filter{
			id:   "TLS_V301_v303",
			desc: "during TLS handshake got record with version 301, but expected version 303",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "tls: received record with version 301 when expecting version 303"),
			)},
		&filter{
			id:   "TLS_BAD_RECORD_MAC",
			desc: "during TLS handshake got a bad record MAC",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "tls: bad record MAC"),
			)},
		&filter{
			id:   "TLS_NOT_TLS",
			desc: "during TLS handshake the first record did not look a like TLS handshake",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "tls: first record does not look like a TLS handshake"),
			)},
		&filter{
			id:   "TLS_UNSUPPORT_APP_PROTOCOLS",
			desc: "during TLS handshake the client requested unsupport application protocols",
			LogMatcher: AndMatchers(
				FieldEquals("file", ""),
				FieldStartsWith("msg", "http: TLS handshake error"),
				FieldContains("msg", "tls: client requested unsupported application protocols"),
			)},
	)

	// channel
	result = append(result,
		&filter{
			id:   "CHANNEL_TLS_NOT_TLS",
			desc: "during tls accept, first data does look like a TLS connection",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/classic_listener.go"),
				FieldContains("msg", "error receiving hello from [tls:"),
				FieldContains("msg", "tls: first record does not look like a TLS handshake"),
			)},
		&filter{
			id:   "CHANNEL_TLS_EOF",
			desc: "during tls accept connection closed",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/classic_listener.go"),
				FieldContains("msg", "error receiving hello from [tls:"),
				FieldContains("msg", "receive error (EOF)"),
			)},
		&filter{
			id:   "CHANNEL_TLS_NO_CERT",
			desc: "during tls accept the client did not provide a certificate",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/classic_listener.go"),
				FieldContains("msg", "error receiving hello from [tls:"),
				FieldContains("msg", "tls: client didn't provide a certificate"),
			)},
		&filter{
			id:   "CHANNEL_ACCEPT_PEER_RESET",
			desc: "during accept the client reset the connection",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/classic_listener.go"),
				FieldContains("msg", "error receiving hello from [tls:"),
				FieldContains("msg", "read: connection reset by peer"),
			)},
		&filter{
			id:   "CHANNEL_ACCEPT_TIMEOUT",
			desc: "during accept the client connection timed out",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/classic_listener.go"),
				FieldContains("msg", "error receiving hello from [tls:"),
				FieldContains("msg", "i/o timeout"),
			)},
	)

	// idle circuit
	result = append(result,
		&filter{
			id:   "IDLE_CIRCUIT_REQUEST",
			desc: "received request to verify that a circuit or set of circuits is still valid",
			LogMatcher: AndMatchers(
				FieldMatches("file", "handler_ctrl/.*_confirmation.go"),
				FieldMatches("msg", "received.*confirmation request"),
			)},
		&filter{
			id:   "IDLE_CIRCUIT_UNROUTE",
			desc: "sent an unroute in response to a idle circuit notification for an invalid circuit",
			LogMatcher: AndMatchers(
				FieldMatches("file", "handler_ctrl/.*_confirmation.go"),
				FieldStartsWith("msg", "sent unroute to "),
			)},
	)

	// forwarding faults
	result = append(result,
		&filter{
			id:   "FORWARDING_FAULT_START",
			desc: "starting circuit forwarding fault handling",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/fault.go"),
				FieldStartsWith("msg", "network fault processing for "),
			)},
		&filter{
			id:   "FORWARDING_FAULT_REROUTE_ERR",
			desc: "error while rerouting circuit which had forwarding fault",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/fault.go"),
				FieldStartsWith("msg", "error rerouting "),
			)},
		&filter{
			id:   "FORWARDING_FAULT_REROUTE_OK",
			desc: "rerouted a circuit in response to a fault",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/fault.go"),
				FieldMatches("msg", "rerouted.*in response to forwarding fault from"),
			)},
		&filter{
			id:   "FORWARDING_FAULT_UNROUTE",
			desc: "sent an unroute in response to a forwarding fault",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/fault.go"),
				FieldStartsWith("msg", "sent unroute for "),
			)},
	)

	// links
	result = append(result,
		&filter{
			id:   "LINK_FAULT",
			desc: "received link fault from a router",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_ctrl/fault.go"),
				FieldStartsWith("msg", "link fault"),
			)},
		&filter{
			id:   "LINK_REROUTE",
			desc: "routing circuits using a link, after link fault",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldStartsWith("msg", "changed link"),
			)},
		&filter{
			id:   "LINK_REROUTE2", // removed post 0.24.2
			desc: "rerouting a link after it faulted",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldContains("func", "rerouteLink"),
				FieldMatches("msg", "link.*changed"),
			)},
		&filter{
			id:   "LINK_FAILED",
			desc: "a router notified us that a link failed",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldContains("func", "LinkConnected"),
				FieldMatches("msg", "link.*failed"),
			)},
		&filter{
			id:   "LINK_REMOVED",
			desc: "removing a link that's been failed long enough that it hit the threshold (30s)",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/assembly.go"),
				FieldContains("func", "clean"),
				FieldStartsWith("msg", "removing"),
			)},
	)

	// circuit creation/routing
	result = append(result,
		&filter{
			id:   "LATE_ROUTE_RESPONSE",
			desc: "a route response received for unknown route, most likely because the route had already timed out",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/routesender.go"),
				FieldMatches("msg", "received successful route status from.*for alien attempt"),
			)},
		&filter{
			id:   "CIRCUIT_CREATE_FAILED",
			desc: "circuit creation failed, giving up after 3 attempts and cleaning up any partially established routes",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldContains("msg", "creation failed after [3] attempts, sending cleanup unroutes"),
			)},
		&filter{
			id:   "REROUTE_CIRCUIT_START",
			desc: "rerouting circuit in response smart routing, link failure or forwarding failure",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldStartsWith("msg", "rerouting "),
			)},
		&filter{
			id:   "REROUTE_CIRCUIT_OK",
			desc: "rerouted circuit in response smart routing, link failure or forwarding failure",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldStartsWith("msg", "rerouted "),
			)},
		&filter{
			id:   "ROUTE_TIMEOUT",
			desc: "a routing attempt failed due to a timeout",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldMatches("msg", `route attempt.*failed \(timeout creating routes`),
			)},
		&filter{
			id:   "CIRCUIT_CREATE_ERR_BAD_SESSION",
			desc: "circuit creation failed because an invalid session was provided",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_edge_ctrl/common.go"),
				FieldEquals("error", "Invalid Session"),
				FieldStartsWith("msg", "responded with error"),
			)},
		// redundant?
		&filter{
			id:   "CIRCUIT_CREATE_ERR_BAD_SESSION-2",
			desc: "when creating a circuit an invalid session was provided",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_edge_ctrl/common.go"),
				FieldEquals("msg", "invalid session"),
			)},
		&filter{
			id:   "CIRCUIT_CREATE_ERR_NO_ROUTE",
			desc: "circuit could not be created because the terminating router failed to dial the server with the error 'no route to host'",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldMatches("msg", "route attempt.*failed.*connect: no route to host"),
			)},
		// redundant?
		&filter{
			id:   "CIRCUIT_CREATE_ERR_NO_ROUTE-2",
			desc: "circuit could not be created because the terminating router failed to dial the server with the error 'no route to host'",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/routesender.go"),
				FieldMatches("msg", "received failed route status.*connect: no route to host"),
			)},
		&filter{
			id:   "CIRCUIT_CREATE_ERR_NO_PATH",
			desc: "circuit creation failed because no route existed for the service",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_edge_ctrl/common.go"),
				FieldEquals("msg", "responded with error"),
				FieldContains("error", "can't route from"),
				FieldContains("error", "source unreachable"),
			)},
		&filter{
			id:   "CIRCUIT_CREATE_ERR_NO_TERMINATORS",
			desc: "circuit creation failed because the service has no terminators",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_edge_ctrl/common.go"),
				FieldEquals("msg", "responded with error"),
				FieldContains("error", "has no terminators"),
			)},
		&filter{
			id:   "CIRCUIT_CREATE_ERR_CONN_REFUSED",
			desc: "circuit could not be created because the terminating router failed to dial the server with the error 'connection refused'",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldMatches("msg", "route attempt.*failed.*connect: connection refused"),
			)},
		// redundant
		&filter{
			id:   "CIRCUIT_CREATE_ERR_CONN_REFUSED-2",
			desc: "circuit could not be created because the terminating router failed to dial the server with the error 'connection refused'",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/routesender.go"),
				FieldMatches("msg", "received failed route status.*connect: connection refused"),
			)},
		&filter{
			id:   "CIRCUIT_CREATE_ERR_IO_TIMEOUT",
			desc: "circuit could not be created because the terminating router failed to dial the server with the error 'i/o timeout'",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldMatches("msg", "route attempt.*failed.*dial.*: i/o timeout"),
			)},
		// redundant
		&filter{
			id:   "CIRCUIT_CREATE_ERR_IO_TIMEOUT-2",
			desc: "circuit could not be created because the terminating router failed to dial the server with the error 'i/o timeout'",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/routesender.go"),
				FieldMatches("msg", "received failed route status.*dial.*: i/o timeout"),
			)},
	)

	// misc
	result = append(result,
		&filter{
			id:   "ROUTER_ALREADY_CONNECTED",
			desc: "router tried to connected but a router with that id is already connected",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/classic_listener.go"),
				FieldContains("msg", "connection handler error"),
				FieldContains("msg", "router already connected"),
			)},
		&filter{
			id:   "ROUTER_UNENROLLED",
			desc: "router tried to connected but either the router doesn't exist or the fingerprint didn't match",
			LogMatcher: AndMatchers(
				FieldContains("file", "channel2/classic_listener.go"),
				FieldContains("msg", "connection handler error"),
				FieldContains("msg", "unenrolled router"),
			)},
		&filter{
			id:   "ROUTER_NOT_TUNNELER",
			desc: "router is trying to use embedded tunneler functionality but the router is not configured as a tunneler",
			LogMatcher: AndMatchers(
				FieldEquals("error", "tunneling not enabled"),
				FieldContains("file", "handler_edge_ctrl"),
			)},
		&filter{
			id:   "REST_RESPONSE_TIMEOUT",
			desc: "while trying to respond to an http request, the handler timed out",
			LogMatcher: AndMatchers(
				OrMatchers(
					FieldContains("file", "response/responder.go"),
					FieldContains("file", "controller/api/responder.go"),
				),
				FieldContains("error", "Handler timeout"),
				FieldEquals("msg", "could not respond with error, producer errored"),
			)},
		// move to debug? Can probably detect not found
		&filter{
			id:   "POSTURE_CHECK_FAIL_SESSION_DELETE_ERR",
			desc: "failed to delete a session after posture check failure b/c the session was already deleted",
			LogMatcher: AndMatchers(
				FieldContains("file", "model/posture_response_model.go"),
				FieldMatches("msg", "error removing session.*due to posture check failure.*"),
				FieldMatches("error", "session with id.*not found"),
			)},
		&filter{
			id:   "TUNNEL_BAD_SESSION",
			desc: "tunnel provided session doesn't match existing api session or service",
			LogMatcher: AndMatchers(
				FieldContains("file", "common_tunnel.go"),
				FieldStartsWith("msg", "required session did not match service or api session"),
			)},
		&filter{
			id:   "SNAPSHOT_DB",
			desc: "the database snapshot has been created",
			LogMatcher: AndMatchers(
				FieldContains("file", "network/network.go"),
				FieldContains("func", "SnapshotDatabase"),
				FieldStartsWith("msg", "snapshotting database"),
			)},
		&filter{
			id:   "XMGMT_CLOSED", // removed to debug post 0.24.2
			desc: "a management channel connection was closed",
			LogMatcher: AndMatchers(
				FieldContains("file", "handler_mgmt/close.go"),
				FieldStartsWith("msg", "closing Xmgmt instances for"),
			)},
	)

	// panics
	result = append(result,
		&filter{
			id:         "PANIC_UNKNOWN",
			desc:       "uncategorized panic",
			LogMatcher: FieldContains("nonJson", "panic"),
		},
	)
	return result
}

func (self *ControllerLogs) summarize(cmd *cobra.Command, args []string) error {
	if err := self.validate(); err != nil {
		return err
	}

	self.handler = &LogSummaryHandler{
		bucketSize:                  self.bucketSize,
		bucketMatches:               map[LogFilter]int{},
		maxUnmatchedLoggedPerBucket: self.maxUnmatched,
		ignore:                      self.ignore,
		formatter:                   self.formatter,
	}

	return ScanJsonLines(args[0], self.processLogEntry)
}

func (self *ControllerLogs) filter(cmd *cobra.Command, args []string) error {
	if err := self.validate(); err != nil {
		return err
	}

	self.handler = &LogFilterHandler{
		maxUnmatched: self.maxUnmatched,
		include:      self.includeFilters,
	}

	return ScanJsonLines(args[0], self.processLogEntry)
}
