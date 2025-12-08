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

//go:build freebsd && cgo

package freebsd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"github.com/elastic/go-sysinfo/internal/registry"
	"github.com/elastic/go-sysinfo/providers/shared"
	"github.com/elastic/go-sysinfo/types"
)

func init() {
	registry.Register(newFreeBSDSystem())
}

type freebsdSystem struct{}

func newFreeBSDSystem() freebsdSystem {
	return freebsdSystem{}
}

func (s freebsdSystem) Host() (types.Host, error) {
	return newHost()
}

type host struct {
	procFS procFS
	info   types.HostInfo
}

func (h *host) Info() types.HostInfo {
	return h.info
}

func (h *host) CPUTime() (types.CPUTimes, error) {
	cpu := types.CPUTimes{}
	r := &reader{}
	r.cpuTime(&cpu)
	return cpu, r.Err()
}

func (h *host) Memory() (*types.HostMemoryInfo, error) {
	m := &types.HostMemoryInfo{}
	r := &reader{}
	r.memInfo(m)
	return m, r.Err()
}

func (h *host) FQDNWithContext(ctx context.Context) (string, error) {
	return shared.FQDNWithContext(ctx)
}

func (h *host) FQDN() (string, error) {
	return h.FQDNWithContext(context.Background())
}

func (h *host) LoadAverage() (*types.LoadAverageInfo, error) {
	load, err := getLoadAverage()
	if err != nil {
		return nil, err
	}

	scale := float64(load.scale)

	return &types.LoadAverageInfo{
		One:     float64(load.load[0]) / scale,
		Five:    float64(load.load[1]) / scale,
		Fifteen: float64(load.load[2]) / scale,
	}, nil
}

func newHost() (*host, error) {
	h := &host{}
	r := &reader{}
	r.architecture(h)
	r.bootTime(h)
	r.hostname(h)
	r.network(h)
	r.kernelVersion(h)
	r.os(h)
	r.time(h)
	r.uniqueID(h)
	return h, r.Err()
}

type reader struct {
	errs []error
}

func (r *reader) addErr(err error) bool {
	if err != nil {
		if !errors.Is(err, types.ErrNotImplemented) {
			r.errs = append(r.errs, err)
		}
		return true
	}
	return false
}

func (r *reader) Err() error {
	return errors.Join(r.errs...)
}

func (r *reader) cpuTime(cpu *types.CPUTimes) {
	times, err := cpuStateTimes()
	if r.addErr(err) {
		return
	}
	*cpu = *times
}

func (r *reader) memInfo(m *types.HostMemoryInfo) {
	// Memory counter calculations:
	//   total = physical memory
	//   used = active + wired
	//   free = free
	//   available = buffers + inactive + cache + free

	pageSize, err := pageSizeBytes()
	if r.addErr(err) {
		return
	}

	m.Total = r.totalPhysicalMem()
	activePages := r.activePageCount()

	m.Metrics = make(map[string]uint64, 6)
	m.Metrics["active_bytes"] = activePages * pageSize

	wirePages := r.wirePageCount()
	m.Metrics["wired_bytes"] = wirePages * pageSize

	inactivePages := r.inactivePageCount()
	m.Metrics["inactive_bytes"] = inactivePages * pageSize

	cachePages := r.cachePageCount()
	m.Metrics["cache_bytes"] = cachePages * pageSize

	freePages := r.freePageCount()
	m.Metrics["free_bytes"] = freePages * pageSize

	buffers := r.buffersUsedBytes()
	m.Metrics["buffer_bytes"] = buffers

	m.Used = (activePages + wirePages) * pageSize
	m.Free = freePages * pageSize
	m.Available = (inactivePages+cachePages+freePages)*pageSize + buffers

	// Virtual (swap) Memory
	swap, err := kvmGetSwapInfo()
	if r.addErr(err) {
		return
	}

	m.VirtualTotal = uint64(swap.Total) * pageSize
	m.VirtualUsed = uint64(swap.Used) * pageSize
	m.VirtualFree = m.VirtualTotal - m.VirtualUsed
}

func (r *reader) architecture(h *host) {
	v, err := architecture()
	if r.addErr(err) {
		return
	}
	h.info.Architecture = v
}

func (r *reader) bootTime(h *host) {
	v, err := bootTime()
	if r.addErr(err) {
		return
	}
	h.info.BootTime = v
}

func (r *reader) hostname(h *host) {
	v, err := os.Hostname()
	if r.addErr(err) {
		return
	}
	h.info.Hostname = v
}

func (r *reader) network(h *host) {
	ips, macs, err := shared.Network()
	if r.addErr(err) {
		return
	}
	h.info.IPs = ips
	h.info.MACs = macs
}

func (r *reader) kernelVersion(h *host) {
	v, err := kernelVersion()
	if r.addErr(err) {
		return
	}
	h.info.KernelVersion = v
}

func (r *reader) os(h *host) {
	v, err := operatingSystem()
	if r.addErr(err) {
		return
	}
	h.info.OS = v
}

func (r *reader) time(h *host) {
	h.info.Timezone, h.info.TimezoneOffsetSec = time.Now().Zone()
}

func (r *reader) uniqueID(h *host) {
	v, err := machineID()
	if r.addErr(err) {
		return
	}
	h.info.UniqueID = v
}

type procFS struct {
	procfs.FS
	mountPoint string
}

func (fs *procFS) path(p ...string) string {
	elem := append([]string{fs.mountPoint}, p...)
	return filepath.Join(elem...)
}

var tickDuration = sync.OnceValues(func() (time.Duration, error) {
	const mib = "kern.clockrate"

	c, err := unix.SysctlClockinfo(mib)
	if err != nil {
		return 0, fmt.Errorf("failed to get %s: %w", mib, err)
	}
	return time.Duration(c.Tick) * time.Microsecond, nil
})

var pageSizeBytes = sync.OnceValues(func() (uint64, error) {
	const mib = "vm.stats.vm.v_page_size"

	v, err := unix.SysctlUint32(mib)
	if err != nil {
		return 0, fmt.Errorf("failed to get %s: %w", mib, err)
	}

	return uint64(v), nil
})

func (r *reader) activePageCount() uint64 {
	const mib = "vm.stats.vm.v_active_count"

	v, err := unix.SysctlUint32(mib)
	if r.addErr(err) {
		return 0
	}
	return uint64(v)
}

// buffersUsedBytes returns the number memory bytes used as disk cache.
func (r *reader) buffersUsedBytes() uint64 {
	const mib = "vfs.bufspace"

	v, err := unix.SysctlUint64(mib)
	if r.addErr(err) {
		return 0
	}

	return v
}

func (r *reader) cachePageCount() uint64 {
	const mib = "vm.stats.vm.v_cache_count"

	v, err := unix.SysctlUint32(mib)
	if r.addErr(err) {
		return 0
	}

	return uint64(v)
}

func (r *reader) freePageCount() uint64 {
	const mib = "vm.stats.vm.v_free_count"

	v, err := unix.SysctlUint32(mib)
	if r.addErr(err) {
		return 0
	}

	return uint64(v)
}

func (r *reader) inactivePageCount() uint64 {
	const mib = "vm.stats.vm.v_inactive_count"

	v, err := unix.SysctlUint32(mib)
	if r.addErr(err) {
		return 0
	}

	return uint64(v)
}

func (r *reader) totalPhysicalMem() uint64 {
	const mib = "hw.physmem"

	v, err := unix.SysctlUint64(mib)
	if r.addErr(err) {
		return 0
	}
	return v
}

func (r *reader) wirePageCount() uint64 {
	const mib = "vm.stats.vm.v_wire_count"

	v, err := unix.SysctlUint32(mib)
	if r.addErr(err) {
		return 0
	}
	return uint64(v)
}

func architecture() (string, error) {
	const mib = "hw.machine"

	arch, err := unix.Sysctl(mib)
	if err != nil {
		return "", fmt.Errorf("failed to get architecture: %w", err)
	}

	return arch, nil
}

func bootTime() (time.Time, error) {
	const mib = "kern.boottime"

	tv, err := unix.SysctlTimeval(mib)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get host uptime: %w", err)
	}

	bootTime := time.Unix(tv.Sec, tv.Usec*int64(time.Microsecond))
	return bootTime, nil
}

const sizeOfUint64 = int(unsafe.Sizeof(uint64(0)))

// cpuStateTimes uses sysctl kern.cp_time to get the amount of time spent in
// different CPU states.
func cpuStateTimes() (*types.CPUTimes, error) {
	tickDuration, err := tickDuration()
	if err != nil {
		return nil, err
	}

	const mib = "kern.cp_time"
	buf, err := unix.SysctlRaw(mib)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s: %w", mib, err)
	}

	var clockTicks [unix.CPUSTATES]uint64
	if len(buf) < len(clockTicks)*sizeOfUint64 {
		return nil, fmt.Errorf("kern.cp_time data is too short (got %d bytes)", len(buf))
	}
	for i := range clockTicks {
		val := *(*uint64)(unsafe.Pointer(&buf[sizeOfUint64*i]))
		clockTicks[i] = val
	}

	return &types.CPUTimes{
		User:   time.Duration(clockTicks[unix.CP_USER]) * tickDuration,
		System: time.Duration(clockTicks[unix.CP_SYS]) * tickDuration,
		Idle:   time.Duration(clockTicks[unix.CP_IDLE]) * tickDuration,
		IRQ:    time.Duration(clockTicks[unix.CP_INTR]) * tickDuration,
		Nice:   time.Duration(clockTicks[unix.CP_NICE]) * tickDuration,
	}, nil
}

func kernelVersion() (string, error) {
	const mib = "kern.osrelease"

	version, err := unix.Sysctl(mib)
	if err != nil {
		return "", fmt.Errorf("failed to get kernel version: %w", err)
	}

	return version, nil
}

type loadAvg struct {
	load  [3]uint32
	scale int
}

func getLoadAverage() (*loadAvg, error) {
	const mib = "vm.loadavg"

	data, err := unix.SysctlRaw(mib)
	if err != nil {
		return nil, err
	}
	load := *(*loadAvg)(unsafe.Pointer((&data[0])))
	return &load, nil
}

func machineID() (string, error) {
	const mib = "kern.hostuuid"

	uuid, err := unix.Sysctl(mib)
	if err != nil {
		return "", fmt.Errorf("failed to get machine id: %w", err)
	}

	return uuid, nil
}

func operatingSystem() (*types.OSInfo, error) {
	info := &types.OSInfo{
		Type:     "freebsd",
		Family:   "freebsd",
		Platform: "freebsd",
	}

	osType, err := unix.Sysctl("kern.ostype")
	if err != nil {
		return info, err
	}
	info.Name = osType

	// Example: 13.0-RELEASE-p11
	osRelease, err := unix.Sysctl("kern.osrelease")
	if err != nil {
		return info, err
	}
	info.Version = osRelease

	releaseParts := strings.Split(osRelease, "-")

	majorMinor := strings.Split(releaseParts[0], ".")
	if len(majorMinor) > 0 {
		info.Major, _ = strconv.Atoi(majorMinor[0])
	}
	if len(majorMinor) > 1 {
		info.Minor, _ = strconv.Atoi(majorMinor[1])
	}

	if len(releaseParts) > 1 {
		info.Build = releaseParts[1]
	}
	if len(releaseParts) > 2 {
		info.Patch, _ = strconv.Atoi(strings.TrimPrefix(releaseParts[2], "p"))
	}

	return info, nil
}
