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
	"bufio"
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/openziti/foundation/util/stringz"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"os"
	"sort"
	"strings"
	"time"
)

type ParseContext struct {
	path       string
	lineNumber int
	eof        bool
	line       string
}

func ScanLines(ctx *ParseContext, callback func(ctx *ParseContext) error) error {
	file, err := os.Open(ctx.path)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		ctx.line = line
		if err := callback(ctx); err != nil {
			return errors.Wrapf(err, "error parsing %v on line %v", ctx.path, ctx.lineNumber)
		}
		ctx.lineNumber++
	}
	ctx.eof = true
	return callback(ctx)
}

type JsonParseContext struct {
	ParseContext
	entry *gabs.Container
	cache map[string]string
}

func (self *JsonParseContext) GetString(path string) string {
	if s, found := self.cache[path]; found {
		return s
	}
	v := self.entry.Search(path)
	if v == nil || v.Data() == nil {
		return ""
	}
	s, ok := v.Data().(string)
	if !ok {
		s = fmt.Sprintf("%v", v.Data())
	}
	self.cache[path] = s
	return s
}

func (self *JsonParseContext) ParseJsonEntry() error {
	input := self.line
	idx := strings.IndexByte(self.line, '{')
	if idx < 0 {
		return nil
	}
	if idx > 0 {
		input = input[idx:]
	}
	entry, err := gabs.ParseJSON([]byte(input))
	if err != nil {
		return err
	}
	self.entry = entry
	self.cache = map[string]string{}
	return nil
}

func ScanJsonLines(ctx *JsonParseContext, callback func(ctx *JsonParseContext) error) error {
	return ScanLines(&ctx.ParseContext, func(*ParseContext) error {
		if ctx.eof {
			return callback(ctx)
		}
		if err := ctx.ParseJsonEntry(); err != nil {
			return err
		}
		return callback(ctx)
	})
}

type LogMatcher interface {
	Matches(ctx *JsonParseContext) (bool, error)
}

type LogFilter interface {
	LogMatcher
	Id() string
	Desc() string
}

type filter struct {
	LogMatcher
	id   string
	desc string
}

func (self *filter) Id() string {
	return self.id
}

func (self *filter) Desc() string {
	return self.desc
}

type JsonLogsParser struct {
	bucketSize                  time.Duration
	currentBucket               time.Time
	filters                     []LogFilter
	bucketMatches               map[LogFilter]int
	unmatched                   int
	maxUnmatchedLoggedPerBucket int
	ignore                      []string
	beforeTime                  string
	afterTime                   string
	include                     LogMatcher
}

func (self *JsonLogsParser) addCommonArgs(cmd *cobra.Command) {
	cmd.Flags().DurationVarP(&self.bucketSize, "interval", "n", time.Hour, "Interval for which to aggregate log messages")
	cmd.Flags().IntVarP(&self.maxUnmatchedLoggedPerBucket, "max-unmatched", "u", 1, "Maximum unmatched log messages to output per bucket")
	cmd.Flags().StringSliceVar(&self.ignore, "ignore", nil, "Filters to ignore")
	cmd.Flags().StringVarP(&self.beforeTime, "before", "B", "", "Process only messages before this timestamp")
	cmd.Flags().StringVarP(&self.afterTime, "after", "A", "", "Process only messages after this timestamp")
}

func (self *JsonLogsParser) validate() error {
	ids := map[string]int{}
	for idx, k := range self.filters {
		if v, found := ids[k.Id()]; found {
			return errors.Errorf("duplicate filter id %v at indices %v and %v", k.Id(), idx, v)
		}
		ids[k.Id()] = idx
	}
	return self.setupDateFilters()
}

func (self *JsonLogsParser) setupDateFilters() error {
	var beforeTime *time.Time
	var afterTime *time.Time

	if self.beforeTime != "" {
		t, err := time.Parse(time.RFC3339, self.beforeTime)
		if err != nil {
			return errors.Errorf("invalid before time argument '%v'. Should use format: '%v'", self.beforeTime, time.RFC3339)
		}
		beforeTime = &t
	}

	if self.afterTime != "" {
		t, err := time.Parse(time.RFC3339, self.afterTime)
		if err != nil {
			return errors.Errorf("invalid after time argument '%v'. Should use format: '%v'", self.afterTime, time.RFC3339)
		}
		afterTime = &t
	}

	if beforeTime == nil {
		if afterTime == nil {
			self.include = AlwaysMatcher{}
		} else {
			self.include = TimePredicate((*afterTime).Before)
		}
	} else {
		if afterTime == nil {
			self.include = TimePredicate((*beforeTime).After)
		} else {
			self.include = TimePredicate(func(t time.Time) bool {
				return t.Before(*beforeTime) && t.After(*afterTime)
			})
		}
	}
	return nil
}

func (self *JsonLogsParser) ShowCategories(*cobra.Command, []string) {
	for _, filter := range self.filters {
		fmt.Printf("%v: %v\n", filter.Id(), filter.Desc())
	}
}

func (self *JsonLogsParser) summarizeLogEntry(ctx *JsonParseContext) error {
	if ctx.eof {
		self.dumpBucket()
		return nil
	}

	if err := self.bucket(ctx); err != nil {
		return err
	}

	match, err := self.include.Matches(ctx)
	if err != nil {
		return err
	}
	if !match {
		return nil
	}

	for _, filter := range self.filters {
		match, err := filter.Matches(ctx)
		if err != nil {
			return err
		}

		if match {
			current := self.bucketMatches[filter]
			self.bucketMatches[filter] = current + 1
			return nil
		}
	}

	self.unmatched++
	if self.unmatched <= self.maxUnmatchedLoggedPerBucket {
		fmt.Printf("WARN: unmatched line: %v\n\n", ctx.line)
	}

	return nil
}

func (self *JsonLogsParser) bucket(ctx *JsonParseContext) error {
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
	return nil
}

func (self *JsonLogsParser) dumpBucket() {
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
