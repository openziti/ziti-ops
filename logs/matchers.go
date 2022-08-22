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
	"regexp"
	"strings"
	"time"
)

type LogMatcher interface {
	Matches(ctx *JsonParseContext) (bool, error)
}

// AndMatchers will return a matcher that will match if all the supplied matchers match
func AndMatchers(matchers ...LogMatcher) LogMatcher {
	return &AndMatcher{matchers: matchers}
}

type AndMatcher struct {
	matchers []LogMatcher
}

func (self *AndMatcher) Matches(ctx *JsonParseContext) (bool, error) {
	for _, matcher := range self.matchers {
		result, err := matcher.Matches(ctx)
		if !result || err != nil {
			return result, err
		}
	}
	return true, nil
}

// OrMatchers will return a matcher that will match if any of the supplied matchers match
func OrMatchers(matchers ...LogMatcher) LogMatcher {
	return &OrMatcher{matchers: matchers}
}

type OrMatcher struct {
	matchers []LogMatcher
}

func (self *OrMatcher) Matches(ctx *JsonParseContext) (bool, error) {
	for _, matcher := range self.matchers {
		result, err := matcher.Matches(ctx)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}
	return false, nil
}

func FieldStartsWith(field, substring string) LogMatcher {
	return &EntryFieldStartsWithMatcher{
		field:  field,
		prefix: substring,
	}
}

type EntryFieldStartsWithMatcher struct {
	field  string
	prefix string
}

func (self *EntryFieldStartsWithMatcher) Matches(ctx *JsonParseContext) (bool, error) {
	fieldValue := ctx.GetString(self.field)
	return strings.HasPrefix(fieldValue, self.prefix), nil
}

func FieldContains(field, substring string) LogMatcher {
	return &EntryFieldContainsMatcher{
		field:     field,
		substring: substring,
	}
}

type EntryFieldContainsMatcher struct {
	field     string
	substring string
}

func (self *EntryFieldContainsMatcher) Matches(ctx *JsonParseContext) (bool, error) {
	fieldValue := ctx.GetString(self.field)
	return strings.Contains(fieldValue, self.substring), nil
}

func FieldEquals(field, substring string) LogMatcher {
	return &EntryFieldEqualsMatcher{
		field: field,
		value: substring,
	}
}

type EntryFieldEqualsMatcher struct {
	field string
	value string
}

func (self *EntryFieldEqualsMatcher) Matches(ctx *JsonParseContext) (bool, error) {
	fieldValue := ctx.GetString(self.field)
	return fieldValue == self.value, nil
}

func FieldMatches(field, expr string) LogMatcher {
	regex, err := regexp.Compile(expr)
	if err != nil {
		panic(err)
	}
	return &EntryFieldMatchesMatcher{
		field: field,
		regex: regex,
	}
}

type EntryFieldMatchesMatcher struct {
	field string
	regex *regexp.Regexp
}

func (self *EntryFieldMatchesMatcher) Matches(ctx *JsonParseContext) (bool, error) {
	fieldValue := ctx.GetString(self.field)
	return self.regex.MatchString(fieldValue), nil
}

type TimePredicate func(t time.Time) bool

func (self TimePredicate) Matches(ctx *JsonParseContext) (bool, error) {
	if ctx.entry != nil {
		ts := ctx.GetString("time")
		if ts == "" {
			return true, nil
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return false, err
		}
		return self(t), nil
	}
	t, err := ctx.getJournaldTime()
	if err != nil {
		return false, err
	}
	return self(t), nil
}

type AlwaysMatcher struct{}

func (a AlwaysMatcher) Matches(*JsonParseContext) (bool, error) {
	return true, nil
}
