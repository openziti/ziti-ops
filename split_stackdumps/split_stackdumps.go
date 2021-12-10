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

package split_stackdumps

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"regexp"
)

/*
This tool can take stackdumps generated from ziti-fabric inspect stackdump and separate them into one dump per file
So if the file contains 4 stackdumps, 2 for controller and 2 for a router with id 001, it will separate them into
controller.0.dump
controller.1.dump
001.0.dump
001.1.dump
*/

func NewSplitStackdumpsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "split-stackdumps </path/to/stackdumps.file>",
		Short: "Splits a file with multiple stackdumps (from ziti fabric inspect) into a file per stackdump",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			run(args[0])
		},
	}
}
func run(targetFile string) {
	inputFileName := targetFile
	inputFile, err := os.Open(inputFileName)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(inputFile)

	var outputFile *os.File

	resultsRegEx, err := regexp.Compile("Results:.*")
	if err != nil {
		panic(err)
	}

	stackdumpIdRegEx, err := regexp.Compile(`(^.*)\.stack[dD]ump$`)
	if err != nil {
		panic(err)
	}

	counts := map[string]int{}

	for scanner.Scan() {
		if scanner.Err() != nil {
			panic(scanner.Err())
		}
		line := scanner.Text()
		if resultsRegEx.MatchString(line) {
			fmt.Printf("Line matches: %v\n", line)
		} else if stackdumpIdRegEx.MatchString(line) {
			stackDumpId := stackdumpIdRegEx.FindStringSubmatch(line)[1]
			count := counts[stackDumpId]
			counts[stackDumpId] = count + 1
			if outputFile != nil {
				if err = outputFile.Close(); err != nil {
					panic(err)
				}
			}
			outputFileName := fmt.Sprintf("%v.%v.dump", stackDumpId, count)
			fmt.Printf("New stackdump found: %v dumping to %v\n", stackDumpId, outputFileName)
			outputFile, err = os.Create(outputFileName)
			if err != nil {
				panic(err)
			}
		} else if outputFile != nil {
			_, err := outputFile.WriteString(line + "\n")
			if err != nil {
				panic(err)
			}
		}
	}
}
