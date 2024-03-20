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

//go:build freebsd

package freebsd

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	hwPhysmemMIB         = "hw.physmem"
	hwPagesizeMIB        = "hw.pagesize"
	vmVmtotalMIB         = "vm.vmtotal"
	vmFreeCount          = "vm.stats.vm.v_free_count"
	vmSwapmaxpagesMIB    = "vm.swap_maxpages"
	vmSwapTotal          = "vm.swap_total"
	vfsNumfreebuffersMIB = "vfs.numfreebuffers"
)

func PageSize() (uint32, error) {
	pageSize, err := unix.SysctlUint32(hwPagesizeMIB)
	if err != nil {
		return 0, fmt.Errorf("failed to get hw.pagesize: %w", err)
	}

	return pageSize, nil
}

func SwapMaxPages() (uint32, error) {
	maxPages, err := unix.SysctlUint32(vmSwapmaxpagesMIB)
	if err != nil {
		return 0, fmt.Errorf("failed to get vm.swap_maxpages: %w", err)
	}

	return maxPages, nil
}

func TotalMemory() (uint64, error) {
	size, err := unix.SysctlUint64(hwPhysmemMIB)
	if err != nil {
		return 0, fmt.Errorf("failed to get hw.physmem: %w", err)
	}

	return size, nil
}

func FreeMemory() (uint32, error) {
	free, err := unix.SysctlUint32(vmFreeCount)
	if err != nil {
		return 0, fmt.Errorf("failed to get vm.stats.vm.v_free_count: %w", err)
	}

	return free, nil
}

func NumFreeBuffers() (uint32, error) {
	var numfreebuffers uint32
	numfreebuffers, err := unix.SysctlUint32(vfsNumfreebuffersMIB)
	if err != nil {
		return 0, fmt.Errorf("failed to get vfs.numfreebuffers: %w", err)
	}

	return numfreebuffers, nil
}

func SwapTotal() (uint32, error) {
	swap, err := unix.SysctlUint32(vmSwapTotal)
	if err != nil {
		return 0, fmt.Errorf("failed to get vm.swap_total: %w", err)
	}

	return swap, nil
}

func SwapUsed() (uint32, error) {
	swap, err := unix.SysctlUint32(vmSwapUsed)
	if err != nil {
		return 0, fmt.Errorf("failed to get vm.swap_x: %w", err)
	}

	return swap, nil
}
