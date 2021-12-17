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
	"fmt"
	"github.com/openziti/foundation/util/stringz"
)

type LogFilterHandler struct {
	unmatched    int
	maxUnmatched int
	include      []string
}

func (self *LogFilterHandler) HandleNewLine(ctx *JsonParseContext) error {
	return nil
}

func (self *LogFilterHandler) HandleEnd(*JsonParseContext) {}

func (self *LogFilterHandler) HandleMatch(ctx *JsonParseContext, logFilter LogFilter) error {
	if stringz.Contains(self.include, logFilter.Id()) {
		fmt.Println(ctx.line)
	}
	return nil
}

func (self LogFilterHandler) HandleUnmatched(ctx *JsonParseContext) error {
	self.unmatched++
	if self.unmatched <= self.maxUnmatched {
		fmt.Printf("WARN: unmatched line: %v\n\n", ctx.line)
	}
	return nil
}
