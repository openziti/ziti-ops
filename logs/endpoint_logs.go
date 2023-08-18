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

func NewEndpointLogsCommand() *cobra.Command {
	endpointLogs := &EndpointLogs{}
	endpointLogs.Init()

	endpointLogsCmd := &cobra.Command{
		Use:     "endpoint-logs",
		Short:   "work with endpoint logs",
		Args:    cobra.ExactArgs(1),
		Aliases: []string{"el"},
	}

	filterEndpointLogsCmd := &cobra.Command{
		Use:     "filter",
		Short:   "filter endpoint log entries",
		Aliases: []string{"f"},
		RunE:    endpointLogs.filter,
	}

	endpointLogs.addFilterArgs(filterEndpointLogsCmd)

	summarizeEndpointLogsCmd := &cobra.Command{
		Use:     "summarize",
		Short:   "Show endpoint log entry summaries",
		Aliases: []string{"s"},
		RunE:    endpointLogs.summarize,
	}

	endpointLogs.addSummarizeArgs(summarizeEndpointLogsCmd)

	endpointLogs.addFilterArgs(endpointLogsCmd)

	showEndpointLogCategoriesCmd := &cobra.Command{
		Use:     "categories",
		Short:   "Show endpoint log entry categories",
		Aliases: []string{"cat"},
		Run:     endpointLogs.ShowCategories,
	}

	endpointLogsCmd.AddCommand(filterEndpointLogsCmd, summarizeEndpointLogsCmd, showEndpointLogCategoriesCmd)

	return endpointLogsCmd
}

type EndpointLogs struct {
	JsonLogsParser
}

func (self *EndpointLogs) Init() {
	self.filters = getEndpointLogFilters()
}

func getEndpointLogFilters() []LogFilter {
	var result []LogFilter

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

func (self *EndpointLogs) summarize(cmd *cobra.Command, args []string) error {
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

func (self *EndpointLogs) filter(cmd *cobra.Command, args []string) error {
	if err := self.validate(); err != nil {
		return err
	}

	self.handler = &LogFilterHandler{
		maxUnmatched: self.maxUnmatched,
		include:      self.includeFilters,
	}

	return ScanJsonLines(args[0], self.processLogEntry)
}
