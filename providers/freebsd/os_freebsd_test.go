// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package freebsd

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jetrmm/go-sysinfo/types"
)

func TestOperatingSystem(t *testing.T) {
	t.Run("freebsd", func(t *testing.T) {
		os, err := getOSInfo("")
		if err != nil {
			t.Fatal(err)
		}
		assert.IsType(t, types.OSInfo{}, *os)
		assert.Equal(t, "freebsd", os.Type)
		assert.Equal(t, "freebsd", os.Family)
		assert.Equal(t, "freebsd", os.Platform)
		assert.Equal(t, "FreeBSD", os.Name)
		assert.Regexp(t, regexp.MustCompile("([0-9]{1,2})\\.([0-5])-(RELEASE|STABLE|CURRENT|RC[0-9]|ALPHA([0-9]{0,2})|BETA([0-9]{0,2}))(-p[0-9])?"), os.Version)
		assert.Regexp(t, regexp.MustCompile("([0-9]{1,2})"), os.Major)
		assert.Regexp(t, regexp.MustCompile("([0-9]{1,2})"), os.Minor)
		assert.Regexp(t, regexp.MustCompile("([0-9]{1,2})"), os.Patch)
		t.Logf("%#v", os)
	})
}
