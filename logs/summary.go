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
	"encoding/json"
	"fmt"
	"github.com/openziti/foundation/util/stringz"
	"github.com/pkg/errors"
	"sort"
	"time"
)

type LogSummaryHandler struct {
	bucketSize                  time.Duration
	currentBucket               time.Time
	bucketMatches               map[LogFilter]int
	unmatched                   int
	maxUnmatchedLoggedPerBucket int
	ignore                      []string
	formatter 					string
}

func (self *LogSummaryHandler) HandleNewLine(ctx *JsonParseContext) error {
	if ctx.entry != nil {
		s := ctx.GetString("time")
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return errors.Errorf("time is in an unexpected format: %v", s)
		}
		interval := t.Truncate(self.bucketSize)
		if interval != self.currentBucket {
			if !self.currentBucket.IsZero() {
				self.dumpBucket()
			}
			self.currentBucket = interval
			self.bucketMatches = map[LogFilter]int{}
			self.unmatched = 0
		}
	}
	return nil
}

func (self *LogSummaryHandler) HandleEnd(*JsonParseContext) {
	self.dumpBucket()
}

func (self *LogSummaryHandler) HandleMatch(ctx *JsonParseContext, logFilter LogFilter) error {
	current := self.bucketMatches[logFilter]
	self.bucketMatches[logFilter] = current + 1
	return nil
}

func (self *LogSummaryHandler) HandleUnmatched(ctx *JsonParseContext) error {
	if ctx.entry != nil {
		self.unmatched++
		if self.unmatched <= self.maxUnmatchedLoggedPerBucket {
			if self.formatter == "text" {
				fmt.Printf("WARN: unmatched line: %v\n\n", ctx.line)
			}
		}
	}
	return nil
}

func (self *LogSummaryHandler) dumpBucket() {
	if self.formatter == "json" {
		self.dumpBucketJson()
	} else {
		self.dumpBucketText()
	}
}

func (self *LogSummaryHandler) dumpBucketText() {
	var filters []LogFilter
	for k := range self.bucketMatches {
		if !stringz.Contains(self.ignore, k.Id()) {
			filters = append(filters, k)
		}
	}
	sort.Slice(filters, func(i, j int) bool {
		return filters[i].Id() < filters[j].Id()
	})
	if len(filters) == 0 && self.unmatched == 0 {
		return
	}
	fmt.Printf("%v\n---------------------------------------------------\n", self.currentBucket.Format(time.RFC3339))
	for _, filter := range filters {
		fmt.Printf("    %v: %0000v\n", filter.Id(), self.bucketMatches[filter])
	}
	if self.unmatched > 0 {
		fmt.Printf("    unmatched: %0000v\n", self.unmatched)
	}
	fmt.Println()
}

func (self *LogSummaryHandler) dumpBucketJson() {
	var filters []LogFilter
	for k := range self.bucketMatches {
		if !stringz.Contains(self.ignore, k.Id()) {
			filters = append(filters, k)
		}
	}
	sort.Slice(filters, func(i, j int) bool {
		return filters[i].Id() < filters[j].Id()
	})
	if len(filters) == 0 && self.unmatched == 0 {
		return
	}

	model := make(map[string]interface{})
	model["timestamp"] = self.currentBucket.Format(time.RFC3339)
	for _, filter := range filters {
		model[filter.Id()] = self.bucketMatches[filter]
	}
	if self.unmatched > 0 {
		model["unmatched"] = fmt.Sprintf("    unmatched: %0000v\n", self.unmatched)
	}

	j, err := json.Marshal(model)
	if err != nil {

	}

	fmt.Printf("%s\n", string(j))

}