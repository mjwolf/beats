package processdb

import (
	"testing"
)


var username string
var found bool

func BenchmarkCached(b *testing.B) {
  c := newNamesCache()
  for i := 0; i < b.N; i++ {
	u, f := c.getUserNameCached("1000")
	username = u
	found = f
  }
}

func BenchmarkUnCached(b *testing.B) {
  c := newNamesCache()
  for i := 0; i < b.N; i++ {
	u, f := c.getUserNameUncached("1000")
	username = u
	found = f
  }
}
