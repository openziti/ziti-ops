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

func NewCtrlLogsCommand() *cobra.Command {
	parseControllerLogs := &ParseControllerLogs{}
	parseControllerLogs.Init()

	parseControllerLogsCmd := &cobra.Command{
		Use:   "ctrl",
		Short: "Parse controller logs",
		Args:  cobra.ExactArgs(1),
		RunE:  parseControllerLogs.run,
	}

	parseControllerLogs.addCommonArgs(parseControllerLogsCmd)

	showControllerLogCategoriesCmd := &cobra.Command{
		Use:   "categories",
		Short: "Show controller log entry categories",
		Run:   parseControllerLogs.ShowCategories,
	}

	parseControllerLogsCmd.AddCommand(showControllerLogCategoriesCmd)

	return parseControllerLogsCmd
}

type ParseControllerLogs struct {
	JsonLogsParser
}

func (self *ParseControllerLogs) Init() {
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
			id:   "REST_RESPONSE_TIMEOUT",
			desc: "while trying to respond to an http request, the handler timed out",
			LogMatcher: AndMatchers(
				FieldContains("file", "response/responder.go"),
				FieldEquals("error", "Handler timeout"),
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
	)
	return result
}

func (self *ParseControllerLogs) run(cmd *cobra.Command, args []string) error {
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
