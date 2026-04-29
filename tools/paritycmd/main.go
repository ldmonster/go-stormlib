// Copyright 2026 go-stormlib Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"os"
)

type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string {
	return e.msg
}

func main() {
	cmd := NewRootCmd(os.Stdout, os.Stderr)
	if err := cmd.Execute(); err != nil {
		var ce *cliError
		if errors.As(err, &ce) {
			if ce.msg != "" {
				fmt.Fprintln(os.Stderr, ce.msg)
			}

			os.Exit(ce.code)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
