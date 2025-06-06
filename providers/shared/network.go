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

package shared

import (
	"net"
)

func Network() (ips, macs []string, err error) {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	// This function fetches all the addresses in a single syscall. Fetching addresses individually for each interface
	// can be expensive when the host has a lot of interfaces. This usually happens when the host is doing virtualized
	// networking for guests, in Kubernetes for example.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil, err
	}
	ips = make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.String())
	}

	macs = make([]string, 0, len(ifcs))
	for _, ifc := range ifcs {
		mac := ifc.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}
	}

	return ips, macs, nil
}
