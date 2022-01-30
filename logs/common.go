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
	"bytes"
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/openziti/foundation/util/stringz"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"os"
	"strings"
	"time"
	"unicode"
)

type ParseContext struct {
	path              string
	journaldTimestamp string
	journald          bool
	lineNumber        int
	eof               bool
	line              string
	process           string
}

func (self *ParseContext) parseJournald() {
	if self.journald {
		if self.line[0] == '-' {
			self.process = "journald"
		} else {
			self.journaldTimestamp = self.line[16:]
			self.line = self.line[16:] // strip timestamp
			_, self.line = splitFirst(self.line, ' ')
			self.process, self.line = splitFirst(self.line, ':')
			self.process, _ = splitFirst(self.process, '[')
		}
	}
}

func (self *ParseContext) getJournaldTime() (time.Time, error) {
	if self.journaldTimestamp == "" {
		return time.Time{}, errors.Errorf("no journald timestamp found on line %v", self.lineNumber)
	}
	return time.Parse("Jan 02 15:04:05", self.journaldTimestamp)
}

func splitFirst(s string, c byte) (string, string) {
	i := strings.IndexByte(s, c)
	if i < 0 {
		return "", s
	}
	if i == len(s)-1 {
		return s, ""
	}
	return s[0:i], s[i+1:]
}

func ScanLines(ctx *ParseContext, callback func(ctx *ParseContext) error) error {
	file, err := os.Open(ctx.path)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(file)

	// skip first line of journald output
	if ctx.journald {
		if scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "-- Logs being at") {
				if err := callback(ctx); err != nil {
					return errors.Wrapf(err, "error parsing %v on line %v", ctx.path, ctx.lineNumber)
				}
			}
			ctx.lineNumber++
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		ctx.line = line
		ctx.parseJournald()
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
	entry   *gabs.Container
	cache   map[string]string
	systemd *string
	nonJson bytes.Buffer
}

func (self *JsonParseContext) GetString(path string) string {
	if path == "nonJson" {
		return self.nonJson.String()
	}
	if path == "systemd" {
		return stringz.OrEmpty(self.systemd)
	}
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
	self.entry = nil
	input := strings.TrimLeftFunc(self.line, unicode.IsSpace)
	if len(input) == 0 || input[0] != '{' {
		return nil
	}

	entry, err := gabs.ParseJSON([]byte(input))
	if err != nil {
		return err
	}
	self.entry = entry
	self.cache = map[string]string{}
	return nil
}

func (self *JsonParseContext) HandleNonJson() {
	self.systemd = nil
	if self.entry == nil {
		if self.process != "systemd" {
			self.nonJson.WriteString(self.line)
			self.nonJson.WriteByte('\n')
		}
	} else {
		self.systemd = &self.line
	}
}

func ScanJsonLines(path string, callback func(ctx *JsonParseContext) error) error {
	ctx := &JsonParseContext{
		ParseContext: ParseContext{
			path:     path,
			journald: true,
		},
	}

	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("panic parsing line %v: %v with err: %v\n", ctx.lineNumber, ctx.line, err)
			panic(err)
		}
	}()

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
	bucketSize     time.Duration
	filters        []LogFilter
	maxUnmatched   int
	ignore         []string
	includeFilters []string
	beforeTime     string
	afterTime      string
	include        LogMatcher
	handler        EntryHandler
	formatter 	   string
}

func (self *JsonLogsParser) addCommonArgs(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&self.beforeTime, "before", "B", "", "Process only messages before this timestamp")
	cmd.Flags().StringVarP(&self.afterTime, "after", "A", "", "Process only messages after this timestamp")
}

func (self *JsonLogsParser) addFilterArgs(cmd *cobra.Command) {
	self.addCommonArgs(cmd)
	cmd.Flags().IntVarP(&self.maxUnmatched, "max-unmatched", "u", 1, "Maximum unmatched log messages to output")
	cmd.Flags().StringSliceVarP(&self.includeFilters, "include", "i", nil, "Filters to include")
}

func (self *JsonLogsParser) addSummarizeArgs(cmd *cobra.Command) {
	self.addCommonArgs(cmd)
	cmd.Flags().DurationVarP(&self.bucketSize, "interval", "n", time.Hour, "Interval for which to aggregate log messages")
	cmd.Flags().IntVarP(&self.maxUnmatched, "max-unmatched", "u", 1, "Maximum unmatched log messages to output per bucket")
	cmd.Flags().StringSliceVarP(&self.ignore, "ignore", "i", nil, "Filters to ignore")
	cmd.Flags().StringVarP(&self.formatter, "output", "o", "text", "Specify output format: [text|json]")
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

type EntryHandler interface {
	HandleEnd(ctx *JsonParseContext)
	HandleNewLine(ctx *JsonParseContext) error
	HandleMatch(ctx *JsonParseContext, logFilter LogFilter) error
	HandleUnmatched(ctx *JsonParseContext) error
}

func (self *JsonLogsParser) processLogEntry(ctx *JsonParseContext) error {
	if ctx.eof {
		if ctx.nonJson.Len() > 0 {
			if err := self.runMatchers(ctx); err != nil {
				return err
			}
		}
		self.handler.HandleEnd(ctx)
		return nil
	}

	if err := self.handler.HandleNewLine(ctx); err != nil {
		return err
	}

	match, err := self.include.Matches(ctx)
	if err != nil {
		return err
	}
	if !match {
		return nil
	}

	ctx.HandleNonJson()

	// if we haven't hit the end of the non-json block, don't match it yet
	if ctx.nonJson.Len() > 0 && ctx.systemd == nil && ctx.entry == nil {
		return nil
	}

	if ctx.nonJson.Len() > 0 {
		if err := self.checkNonJson(ctx); err != nil {
			return err
		}
	}

	err = self.runMatchers(ctx)
	if ctx.nonJson.Len() > 0 {
		ctx.nonJson.Truncate(0)
	}
	return err
}

func (self *JsonLogsParser) checkNonJson(ctx *JsonParseContext) error {
	// we're past the non-json, so save current line data and clear it
	entry := ctx.entry
	line := ctx.line
	ctx.line = ctx.nonJson.String()
	ctx.entry = nil

	if err := self.runMatchers(ctx); err != nil {
		return err
	}

	ctx.nonJson.Truncate(0)

	// restore current line data
	ctx.entry = entry
	ctx.line = line

	return nil
}

func (self *JsonLogsParser) runMatchers(ctx *JsonParseContext) error {
	for _, filter := range self.filters {
		match, err := filter.Matches(ctx)
		if err != nil {
			return err
		}

		if match {
			return self.handler.HandleMatch(ctx, filter)
		}
	}

	return self.handler.HandleUnmatched(ctx)
}
