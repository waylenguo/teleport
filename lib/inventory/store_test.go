/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package inventory

import (
	"fmt"
	"sync"
	"testing"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/stretchr/testify/require"
)

/*
goos: linux
goarch: amd64
pkg: github.com/gravitational/teleport/lib/inventory
cpu: Intel(R) Xeon(R) CPU @ 2.80GHz
BenchmarkStore-4               3         480249642 ns/op
*/
func BenchmarkStore(b *testing.B) {
	const insertions = 100_000
	const unique_servers = 10_000
	const read_mod = 100

	for n := 0; n < b.N; n++ {
		store := NewStore()
		var wg sync.WaitGroup

		for i := 0; i < insertions; i++ {
			wg.Add(1)
			go func(sn int) {
				defer wg.Done()
				serverID := fmt.Sprintf("server-%d", sn%unique_servers)
				handle := &upstreamHandle{
					hello: proto.UpstreamInventoryHello{
						ServerID: serverID,
					},
				}
				store.Insert(handle)
				_, ok := store.Get(serverID)
				require.True(b, ok)
				if sn%read_mod == 0 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						var foundServer bool
						store.Iter(func(h UpstreamHandle) {
							if h.Hello().ServerID == serverID {
								foundServer = true
							}
						})
						require.True(b, foundServer)
					}()
				}
			}(i)
		}
		wg.Wait()
		require.True(b, store.Len() == unique_servers)
	}
}
