package baseline

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// DefaultAnyTLSPaddingScheme is AnyTLS's default padding scheme, copied from
// anytls-go v0.0.13 (proxy/padding/padding.go, also docs/protocol.md).
//
// "stop=8" pads the client's writes 0 to 7. Write 0 is the authentication
// packet, which carries padding0 bytes of padding. From write 1 on, each
// write is split into TLS writes of the listed sizes: a range "a-b" is a
// random size in [a, b), and "c" stops early if the payload is used up.
// Leftover space in the last piece is filled with a cmdWaste frame; pieces
// listed after the payload runs out (without a "c" in between) are sent as
// pure padding.
const DefaultAnyTLSPaddingScheme = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`

// checkMark is a "c" entry in a padding scheme.
const checkMark = -1

type sizeRange struct{ lo, hi int }

// paddingScheme is a parsed AnyTLS padding scheme.
type paddingScheme struct {
	md5  string // lowercase hex MD5 of the raw scheme, sent in cmdSettings
	stop uint32
	pkts map[uint32][]sizeRange // a checkMark entry has lo == hi == checkMark
}

// parsePaddingScheme parses lines of "key=value". Like anytls-go it skips
// malformed ranges, but it requires a valid stop.
func parsePaddingScheme(raw string) (*paddingScheme, error) {
	sum := md5.Sum([]byte(raw))
	s := &paddingScheme{md5: hex.EncodeToString(sum[:]), pkts: make(map[uint32][]sizeRange)}
	haveStop := false
	for line := range strings.SplitSeq(raw, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(k, 10, 32)
		if k == "stop" {
			n, err = strconv.ParseUint(v, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("baseline: padding scheme: bad stop %q", v)
			}
			s.stop, haveStop = uint32(n), true
			continue
		}
		if err != nil {
			continue
		}
		var ranges []sizeRange
		for r := range strings.SplitSeq(v, ",") {
			if r == "c" {
				ranges = append(ranges, sizeRange{checkMark, checkMark})
				continue
			}
			a, b, ok := strings.Cut(r, "-")
			if !ok {
				continue
			}
			lo, err1 := strconv.Atoi(a)
			hi, err2 := strconv.Atoi(b)
			if err1 != nil || err2 != nil || lo <= 0 || hi <= 0 {
				continue
			}
			ranges = append(ranges, sizeRange{min(lo, hi), max(lo, hi)})
		}
		s.pkts[uint32(n)] = ranges
	}
	if !haveStop {
		return nil, fmt.Errorf("baseline: padding scheme has no stop")
	}
	return s, nil
}

// sizes draws the record sizes for client write number pkt, with checkMark
// for "c". It returns nil for writes the scheme does not mention.
func (s *paddingScheme) sizes(pkt uint32) []int {
	ranges := s.pkts[pkt]
	if len(ranges) == 0 {
		return nil
	}
	out := make([]int, len(ranges))
	for i, r := range ranges {
		switch {
		case r.lo == checkMark:
			out[i] = checkMark
		case r.lo == r.hi:
			out[i] = r.lo
		default:
			out[i] = r.lo + rand.IntN(r.hi-r.lo) // [lo, hi), as anytls-go draws it
		}
	}
	return out
}

var defaultPadding = func() *paddingScheme {
	s, err := parsePaddingScheme(DefaultAnyTLSPaddingScheme)
	if err != nil {
		panic(err)
	}
	return s
}()
