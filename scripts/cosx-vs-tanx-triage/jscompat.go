// JavaScript and Node.js semantics that tanx.ts relies on: a JSON value
// model, UTF-16 strings, whitespace, Number formatting, posix path helpers,
// decodeURIComponent, fs error text, and localeCompare ordering.

package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

type jsError struct {
	name    string
	message string
}

func throwError(name, format string, args ...any) {
	panic(&jsError{name: name, message: fmt.Sprintf(format, args...)})
}

func throwType(format string, args ...any) { throwError("TypeError", format, args...) }

type kind uint8

const (
	kUndef kind = iota
	kNull
	kBool
	kNum
	kStr
	kArr
	kObj
)

type value struct {
	k   kind
	b   bool
	n   float64
	s   string // WTF-8, so lone UTF-16 surrogates from JSON escapes survive.
	arr []*value
	obj *object
}

type object struct {
	keys []string
	vals map[string]*value
}

var undefinedValue = &value{k: kUndef}

func strValue(s string) *value { return &value{k: kStr, s: s} }

func numValue(n float64) *value { return &value{k: kNum, n: n} }

func (v *value) nullish() bool { return v == nil || v.k == kUndef || v.k == kNull }

func (v *value) isString() bool { return v != nil && v.k == kStr }

func (v *value) isNumber() bool { return v != nil && v.k == kNum }

func (v *value) isUndef() bool { return v == nil || v.k == kUndef }

func (v *value) isObjLike() bool { return v != nil && (v.k == kObj || v.k == kArr) }

func nullName(v *value) string {
	if v != nil && v.k == kNull {
		return "null"
	}
	return "undefined"
}

// get is `v.key`: it throws on null or undefined.
func get(v *value, key string) *value {
	if v.nullish() {
		throwType("Cannot read properties of %s (reading '%s')", nullName(v), key)
	}
	return member(v, key)
}

// opt is `v?.key`.
func opt(v *value, key string) *value {
	if v.nullish() {
		return undefinedValue
	}
	return member(v, key)
}

func member(v *value, key string) *value {
	switch v.k {
	case kStr:
		units := toUTF16(v.s)
		if key == "length" {
			return numValue(float64(len(units)))
		}
		if i, ok := arrayIndex(key); ok && i < len(units) {
			return strValue(fromUTF16(units[i : i+1]))
		}
	case kArr:
		if key == "length" {
			return numValue(float64(len(v.arr)))
		}
		if i, ok := arrayIndex(key); ok && i < len(v.arr) {
			return v.arr[i]
		}
	case kObj:
		if x, ok := v.obj.vals[key]; ok {
			return x
		}
	}
	return undefinedValue
}

// coalesce is `a ?? b`.
func coalesce(a, b *value) *value {
	if a.nullish() {
		return b
	}
	return a
}

// or is `a || b`.
func or(a, b *value) *value {
	if truthy(a) {
		return a
	}
	return b
}

func arrayIndex(key string) (int, bool) {
	if key == "" || len(key) > 10 {
		return 0, false
	}
	if key != "0" && key[0] == '0' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > 4294967294 {
		return 0, false
	}
	return n, true
}

// iterate is `for (const x of v)` / `[...v]`.
func iterate(v *value, what string) []*value {
	if v != nil {
		switch v.k {
		case kArr:
			return v.arr
		case kStr:
			units := toUTF16(v.s)
			var out []*value
			for i := 0; i < len(units); i++ {
				if utf16.IsSurrogate(rune(units[i])) && units[i] < 0xDC00 && i+1 < len(units) && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF {
					out = append(out, strValue(fromUTF16(units[i:i+2])))
					i++
				} else {
					out = append(out, strValue(fromUTF16(units[i:i+1])))
				}
			}
			return out
		}
	}
	throwType("%s is not iterable", what)
	return nil
}

func truthy(v *value) bool {
	if v == nil {
		return false
	}
	switch v.k {
	case kUndef, kNull:
		return false
	case kBool:
		return v.b
	case kNum:
		return v.n != 0 && !math.IsNaN(v.n)
	case kStr:
		return v.s != ""
	}
	return true
}

// toStr is String(v) / template literal interpolation.
func toStr(v *value) string {
	if v == nil {
		return "undefined"
	}
	switch v.k {
	case kUndef:
		return "undefined"
	case kNull:
		return "null"
	case kBool:
		if v.b {
			return "true"
		}
		return "false"
	case kNum:
		return jsNumber(v.n)
	case kStr:
		return v.s
	case kArr:
		parts := make([]string, len(v.arr))
		for i, x := range v.arr {
			if !x.nullish() {
				parts[i] = toStr(x)
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

// toNumber is Number(v).
func toNumber(v *value) float64 {
	if v == nil {
		return math.NaN()
	}
	switch v.k {
	case kUndef:
		return math.NaN()
	case kNull:
		return 0
	case kBool:
		if v.b {
			return 1
		}
		return 0
	case kNum:
		return v.n
	case kStr:
		return stringToNumber(v.s)
	}
	return stringToNumber(toStr(v))
}

func stringToNumber(s string) float64 {
	s = jsTrim(s)
	if s == "" {
		return 0
	}
	switch s {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			n, err := strconv.ParseUint(s[2:], base, 64)
			if err != nil {
				return math.NaN()
			}
			return float64(n)
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
			return math.NaN()
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return math.NaN()
	}
	return f
}

// jsNumber is Number.prototype.toString() for base 10.
func jsNumber(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case f == 0:
		return "0"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expText, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expText)
	k := len(digits)
	n := exp + 1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	expSign := "+"
	if n-1 < 0 {
		expSign = "-"
	}
	out := digits[:1]
	if k > 1 {
		out += "." + digits[1:]
	}
	return sign + out + "e" + expSign + strconv.Itoa(absInt(n-1))
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// sameValueZeroKey gives Map/Set identity for a value.
func sameValueZeroKey(v *value) string {
	if v == nil {
		return "u"
	}
	switch v.k {
	case kUndef:
		return "u"
	case kNull:
		return "n"
	case kBool:
		return "b" + toStr(v)
	case kNum:
		return "d" + toStr(v)
	case kStr:
		return "s" + v.s
	}
	return fmt.Sprintf("o%p", v)
}

type entry struct {
	key string
	val *value
}

func orderedKeys(o *object) []string {
	var index []string
	var named []string
	for _, k := range o.keys {
		if _, ok := arrayIndex(k); ok {
			index = append(index, k)
		} else {
			named = append(named, k)
		}
	}
	sort.SliceStable(index, func(i, j int) bool {
		a, _ := arrayIndex(index[i])
		b, _ := arrayIndex(index[j])
		return a < b
	})
	return append(index, named...)
}

// entries is Object.entries(v).
func entries(v *value) []entry {
	var out []entry
	switch v.k {
	case kObj:
		for _, k := range orderedKeys(v.obj) {
			out = append(out, entry{k, v.obj.vals[k]})
		}
	case kArr:
		for i, x := range v.arr {
			out = append(out, entry{strconv.Itoa(i), x})
		}
	case kStr:
		units := toUTF16(v.s)
		for i := range units {
			out = append(out, entry{strconv.Itoa(i), strValue(fromUTF16(units[i : i+1]))})
		}
	}
	return out
}

// stringify is JSON.stringify(v) for JSON-derived values.
func stringify(v *value) string {
	var b strings.Builder
	writeJSON(&b, v)
	return b.String()
}

func writeJSON(b *strings.Builder, v *value) {
	switch v.k {
	case kNull, kUndef:
		b.WriteString("null")
	case kBool:
		b.WriteString(toStr(v))
	case kNum:
		if math.IsNaN(v.n) || math.IsInf(v.n, 0) {
			b.WriteString("null")
		} else {
			b.WriteString(jsNumber(v.n))
		}
	case kStr:
		quoteJSON(b, v.s)
	case kArr:
		b.WriteByte('[')
		for i, x := range v.arr {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, x)
		}
		b.WriteByte(']')
	case kObj:
		b.WriteByte('{')
		for i, k := range orderedKeys(v.obj) {
			if i > 0 {
				b.WriteByte(',')
			}
			quoteJSON(b, k)
			b.WriteByte(':')
			writeJSON(b, v.obj.vals[k])
		}
		b.WriteByte('}')
	}
}

func quoteJSON(b *strings.Builder, s string) {
	units := toUTF16(s)
	b.WriteByte('"')
	for i := 0; i < len(units); i++ {
		c := units[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(b, `\u%04x`, c)
		case c >= 0xD800 && c <= 0xDBFF && i+1 < len(units) && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF:
			b.WriteRune(utf16.DecodeRune(rune(c), rune(units[i+1])))
			i++
		case c >= 0xD800 && c <= 0xDFFF:
			fmt.Fprintf(b, `\u%04x`, c)
		default:
			b.WriteRune(rune(c))
		}
	}
	b.WriteByte('"')
}

// decodeUTF8 decodes bytes the way Node's Buffer#toString("utf8") does,
// replacing each maximal invalid subpart with U+FFFD.
func decodeUTF8(data []byte) []uint16 {
	out := make([]uint16, 0, len(data))
	emit := func(r rune) {
		if r >= 0x10000 {
			a, b := utf16.EncodeRune(r)
			out = append(out, uint16(a), uint16(b))
		} else {
			out = append(out, uint16(r))
		}
	}
	var cp rune
	needed, seen := 0, 0
	lower, upper := byte(0x80), byte(0xBF)
	for i := 0; i < len(data); {
		c := data[i]
		if needed == 0 {
			switch {
			case c <= 0x7F:
				emit(rune(c))
			case c >= 0xC2 && c <= 0xDF:
				needed, cp = 1, rune(c&0x1F)
			case c >= 0xE0 && c <= 0xEF:
				if c == 0xE0 {
					lower = 0xA0
				} else if c == 0xED {
					upper = 0x9F
				}
				needed, cp = 2, rune(c&0x0F)
			case c >= 0xF0 && c <= 0xF4:
				if c == 0xF0 {
					lower = 0x90
				} else if c == 0xF4 {
					upper = 0x8F
				}
				needed, cp = 3, rune(c&0x07)
			default:
				emit(utf8.RuneError)
			}
			i++
			continue
		}
		if c < lower || c > upper {
			cp, needed, seen = 0, 0, 0
			lower, upper = 0x80, 0xBF
			emit(utf8.RuneError)
			continue
		}
		lower, upper = 0x80, 0xBF
		cp = cp<<6 | rune(c&0x3F)
		seen++
		i++
		if seen == needed {
			emit(cp)
			cp, needed, seen = 0, 0, 0
		}
	}
	if needed != 0 {
		emit(utf8.RuneError)
	}
	return out
}

// toUTF16 converts a WTF-8 string to UTF-16 code units.
func toUTF16(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			out = append(out, uint16(c))
			i++
			continue
		}
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2] >= 0x80 && s[i+2] <= 0xBF {
			out = append(out, uint16(0xD000|uint16(s[i+1]&0x3F)<<6|uint16(s[i+2]&0x3F)))
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r >= 0x10000 {
			a, b := utf16.EncodeRune(r)
			out = append(out, uint16(a), uint16(b))
		} else {
			out = append(out, uint16(r))
		}
		i += size
	}
	return out
}

// fromUTF16 converts UTF-16 code units to WTF-8.
func fromUTF16(units []uint16) string {
	var b strings.Builder
	for i := 0; i < len(units); i++ {
		c := units[i]
		switch {
		case c >= 0xD800 && c <= 0xDBFF && i+1 < len(units) && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF:
			b.WriteRune(utf16.DecodeRune(rune(c), rune(units[i+1])))
			i++
		case c >= 0xD800 && c <= 0xDFFF:
			b.WriteByte(byte(0xE0 | c>>12))
			b.WriteByte(byte(0x80 | (c>>6)&0x3F))
			b.WriteByte(byte(0x80 | c&0x3F))
		default:
			b.WriteRune(rune(c))
		}
	}
	return b.String()
}

// toOutput encodes a string the way Node writes it: lone surrogates become U+FFFD.
func toOutput(s string) string { return string(utf16.Decode(toUTF16(s))) }

func utf16Len(s string) int { return len(toUTF16(s)) }

func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// jsTrim is String.prototype.trim.
func jsTrim(s string) string {
	start := 0
	for start < len(s) {
		r, size := utf8.DecodeRuneInString(s[start:])
		if r == utf8.RuneError || !isJSSpace(r) {
			break
		}
		start += size
	}
	end := len(s)
	for end > start {
		r, size := utf8.DecodeLastRuneInString(s[start:end])
		if r == utf8.RuneError || !isJSSpace(r) {
			break
		}
		end -= size
	}
	return s[start:end]
}

// jsLower is String.prototype.toLowerCase for the cases that matter here.
func jsLower(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			b.WriteString(s[i : i+3])
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == 0x130 {
			b.WriteString("i\u0307")
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
		i += size
	}
	return b.String()
}

// asciiLower lowercases A-Z only, which is how a non-unicode /i regex folds
// ASCII patterns.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func requireString(v *value, method string) string {
	if !v.isString() {
		throwType("value.%s is not a function", method)
	}
	return v.s
}

const jsWS = `\t\n\x0B\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

func normalizeString(path string, allowAboveRoot bool) string {
	res := ""
	lastSegmentLength := 0
	lastSlash := -1
	dots := 0
	var code byte
	for i := 0; i <= len(path); i++ {
		if i < len(path) {
			code = path[i]
		} else if code == '/' {
			break
		} else {
			code = '/'
		}
		if code == '/' {
			if lastSlash == i-1 || dots == 1 {
				// no-op
			} else if dots == 2 {
				if len(res) < 2 || lastSegmentLength != 2 || res[len(res)-1] != '.' || res[len(res)-2] != '.' {
					if len(res) > 2 {
						idx := strings.LastIndexByte(res, '/')
						if idx == -1 {
							res = ""
							lastSegmentLength = 0
						} else {
							res = res[:idx]
							lastSegmentLength = len(res) - 1 - strings.LastIndexByte(res, '/')
						}
						lastSlash = i
						dots = 0
						continue
					} else if len(res) != 0 {
						res = ""
						lastSegmentLength = 0
						lastSlash = i
						dots = 0
						continue
					}
				}
				if allowAboveRoot {
					if len(res) > 0 {
						res += "/.."
					} else {
						res = ".."
					}
					lastSegmentLength = 2
				}
			} else {
				if len(res) > 0 {
					res += "/" + path[lastSlash+1:i]
				} else {
					res = path[lastSlash+1 : i]
				}
				lastSegmentLength = i - lastSlash - 1
			}
			lastSlash = i
			dots = 0
		} else if code == '.' && dots != -1 {
			dots++
		} else {
			dots = -1
		}
	}
	return res
}

func nodeNormalize(path string) string {
	if path == "" {
		return "."
	}
	isAbsolute := path[0] == '/'
	trailing := path[len(path)-1] == '/'
	path = normalizeString(path, !isAbsolute)
	if path == "" {
		if isAbsolute {
			return "/"
		}
		if trailing {
			return "./"
		}
		return "."
	}
	if trailing {
		path += "/"
	}
	if isAbsolute {
		return "/" + path
	}
	return path
}

func nodeJoin(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		return "."
	}
	return nodeNormalize(strings.Join(kept, "/"))
}

func cwd() string {
	dir, err := syscall.Getwd()
	if err != nil {
		dir, _ = os.Getwd()
	}
	return dir
}

func nodeResolve(parts ...string) string {
	resolved := ""
	absolute := false
	for i := len(parts) - 1; i >= -1 && !absolute; i-- {
		var path string
		if i >= 0 {
			path = parts[i]
		} else {
			path = cwd()
		}
		if path == "" {
			continue
		}
		resolved = path + "/" + resolved
		absolute = path[0] == '/'
	}
	resolved = normalizeString(resolved, !absolute)
	if absolute {
		return "/" + resolved
	}
	if resolved == "" {
		return "."
	}
	return resolved
}

func nodeRelative(from, to string) string {
	if from == to {
		return ""
	}
	from = nodeResolve(from)
	to = nodeResolve(to)
	if from == to {
		return ""
	}
	fromStart, fromEnd := 1, len(from)
	fromLen := fromEnd - fromStart
	toStart := 1
	toLen := len(to) - toStart
	length := fromLen
	if toLen < length {
		length = toLen
	}
	lastCommonSep := -1
	i := 0
	for ; i < length; i++ {
		fc := from[fromStart+i]
		if fc != to[toStart+i] {
			break
		} else if fc == '/' {
			lastCommonSep = i
		}
	}
	if i == length {
		if toLen > length {
			if to[toStart+i] == '/' {
				return to[toStart+i+1:]
			}
			if i == 0 {
				return to[toStart+i:]
			}
		} else if fromLen > length {
			if from[fromStart+i] == '/' {
				lastCommonSep = i
			} else if i == 0 {
				lastCommonSep = 0
			}
		}
	}
	out := ""
	for i = fromStart + lastCommonSep + 1; i <= fromEnd; i++ {
		if i == fromEnd || from[i] == '/' {
			if out == "" {
				out += ".."
			} else {
				out += "/.."
			}
		}
	}
	return out + to[toStart+lastCommonSep:]
}

func nodeBasename(path string) string {
	start, end := 0, -1
	matchedSlash := true
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if !matchedSlash {
				start = i + 1
				break
			}
		} else if end == -1 {
			matchedSlash = false
			end = i + 1
		}
	}
	if end == -1 {
		return ""
	}
	return path[start:end]
}

func nodeDirname(path string) string {
	if path == "" {
		return "."
	}
	hasRoot := path[0] == '/'
	end := -1
	matchedSlash := true
	for i := len(path) - 1; i >= 1; i-- {
		if path[i] == '/' {
			if !matchedSlash {
				end = i
				break
			}
		} else {
			matchedSlash = false
		}
	}
	if end == -1 {
		if hasRoot {
			return "/"
		}
		return "."
	}
	if hasRoot && end == 1 {
		return "//"
	}
	return path[:end]
}

// decodeURIComponent follows ECMAScript's Decode with an empty reserved set.
func decodeURIComponent(s string) string {
	var b strings.Builder
	malformed := func() { throwError("URIError", "URI malformed") }
	hexByte := func(k int) byte {
		if k+2 >= len(s) {
			malformed()
		}
		if s[k] != '%' {
			malformed()
		}
		hi, lo := hexValue(int(s[k+1])), hexValue(int(s[k+2]))
		if hi < 0 || lo < 0 {
			malformed()
		}
		return byte(hi<<4 | lo)
	}
	for k := 0; k < len(s); k++ {
		if s[k] != '%' {
			b.WriteByte(s[k])
			continue
		}
		first := hexByte(k)
		k += 2
		if first < 0x80 {
			b.WriteByte(first)
			continue
		}
		n := 0
		switch {
		case first&0xE0 == 0xC0:
			n = 2
		case first&0xF0 == 0xE0:
			n = 3
		case first&0xF8 == 0xF0:
			n = 4
		default:
			malformed()
		}
		octets := []byte{first}
		for j := 1; j < n; j++ {
			k++
			next := hexByte(k)
			if next&0xC0 != 0x80 {
				malformed()
			}
			octets = append(octets, next)
			k += 2
		}
		r, size := utf8.DecodeRune(octets)
		if size != len(octets) {
			malformed()
		}
		b.WriteRune(r)
	}
	return b.String()
}

var errnoText = map[syscall.Errno][2]string{
	syscall.ENOENT:       {"ENOENT", "no such file or directory"},
	syscall.EACCES:       {"EACCES", "permission denied"},
	syscall.EPERM:        {"EPERM", "operation not permitted"},
	syscall.EISDIR:       {"EISDIR", "illegal operation on a directory"},
	syscall.ENOTDIR:      {"ENOTDIR", "not a directory"},
	syscall.ELOOP:        {"ELOOP", "too many symbolic links encountered"},
	syscall.ENAMETOOLONG: {"ENAMETOOLONG", "name too long"},
	syscall.EMFILE:       {"EMFILE", "too many open files"},
	syscall.EIO:          {"EIO", "i/o error"},
	syscall.EEXIST:       {"EEXIST", "file already exists"},
	syscall.ENOSPC:       {"ENOSPC", "no space left on device"},
	syscall.EROFS:        {"EROFS", "read-only file system"},
	syscall.EBUSY:        {"EBUSY", "resource busy or locked"},
	syscall.ENXIO:        {"ENXIO", "no such device or address"},
}

func nodeFsMessage(err error, op, path string) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if t, ok := errnoText[errno]; ok {
			return fmt.Sprintf("%s: %s, %s '%s'", t[0], t[1], op, path)
		}
		return fmt.Sprintf("UNKNOWN: %s, %s '%s'", errno.Error(), op, path)
	}
	return err.Error()
}

func exists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// localeCompare approximates ICU root collation (Node's default
// String.prototype.localeCompare) for ASCII: punctuation, then digits, then
// letters compared case-insensitively first, lowercase before uppercase.
var collationPrimary [128]int

func init() {
	order := "\t\n\v\f\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789"
	w := 1
	for i := 0; i < len(order); i++ {
		collationPrimary[order[i]] = w
		w++
	}
	for c := 'a'; c <= 'z'; c++ {
		collationPrimary[c] = w
		collationPrimary[c-32] = w
		w++
	}
}

func collationKeys(s string) ([]int, []int) {
	var primary, tertiary []int
	for _, r := range s {
		if r < 128 {
			w := collationPrimary[r]
			if w == 0 {
				continue // control characters are ignorable
			}
			primary = append(primary, w)
			if r >= 'A' && r <= 'Z' {
				tertiary = append(tertiary, 1)
			} else {
				tertiary = append(tertiary, 0)
			}
			continue
		}
		primary = append(primary, 1000+int(r))
		tertiary = append(tertiary, 0)
	}
	return primary, tertiary
}

func compareInts(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func localeCompare(a, b string) int {
	ap, at := collationKeys(a)
	bp, bt := collationKeys(b)
	if c := compareInts(ap, bp); c != 0 {
		return c
	}
	return compareInts(at, bt)
}

// compareUTF16 is the default Array.prototype.sort order.
func compareUTF16(a, b string) bool {
	ua, ub := toUTF16(a), toUTF16(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
