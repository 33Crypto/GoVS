// Command cosx-vs-tanx-triage summarizes CodeQL SARIF for the
// cosx-vs-tanx-triage pipeline. It is a Go port of scripts/tanx.ts.
//
// It reads SARIF results plus extraction and build logs, writes a markdown
// summary to GITHUB_STEP_SUMMARY, and also writes that summary to disk so
// the workflow can upload it with the SARIF artifact.
//
//	go run scripts/cosx-vs-tanx-triage.go \
//	  --sarif codeql-results \
//	  --summary codeql-results/tanx-summary.md \
//	  --logs "$RUNNER_TEMP/codeql_databases"
//
// Standard library only. Findings do not fail the process. A missing or
// unreadable SARIF is reported in the summary and exits with code 2, so a
// broken analysis is never mistaken for a clean one.
//
// The output is meant to match tanx.ts byte for byte. To get there, this file
// reproduces the JavaScript behaviour tanx.ts relies on: JSON.parse (including
// its error messages and key order), UTF-16 string lengths, JavaScript
// whitespace and regex semantics, Node's path helpers, Number-to-string
// conversion, and localeCompare ordering for ASCII paths.
package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Errors that mirror an uncaught JavaScript exception (exit code 1).

type jsError struct {
	name    string
	message string
}

func throwError(name, format string, args ...any) {
	panic(&jsError{name: name, message: fmt.Sprintf(format, args...)})
}

func throwType(format string, args ...any) { throwError("TypeError", format, args...) }

// ---------------------------------------------------------------------------
// A small model of JSON-derived JavaScript values.

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

func strValue(s string) *value   { return &value{k: kStr, s: s} }
func numValue(n float64) *value  { return &value{k: kNum, n: n} }
func (v *value) nullish() bool   { return v == nil || v.k == kUndef || v.k == kNull }
func (v *value) isString() bool  { return v != nil && v.k == kStr }
func (v *value) isNumber() bool  { return v != nil && v.k == kNum }
func (v *value) isUndef() bool   { return v == nil || v.k == kUndef }
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

// ---------------------------------------------------------------------------
// Strings: UTF-8 decoding (WHATWG), UTF-16 and WTF-8 conversion.

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

// ---------------------------------------------------------------------------
// JSON.parse, including V8's error messages.

type jsonParser struct {
	src []uint16
	pos int
}

type jsonError struct{ message string }

func parseJSON(src []uint16) (v *value, err error) {
	p := &jsonParser{src: src}
	defer func() {
		if r := recover(); r != nil {
			if je, ok := r.(*jsonError); ok {
				v, err = nil, errors.New(je.message)
				return
			}
			panic(r)
		}
	}()
	p.skipWS()
	v = p.parseValue()
	p.skipWS()
	if p.pos < len(p.src) {
		p.failAt("Unexpected non-whitespace character after JSON")
	}
	return v, nil
}

func (p *jsonParser) skipWS() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) lineColumn() (int, int) {
	line := 1
	lastBreak := 0
	i := 0
	for ; i < p.pos; i++ {
		if p.src[i] == '\r' && i < p.pos-1 && p.src[i+1] == '\n' {
			i++
		}
		if p.src[i] == '\r' || p.src[i] == '\n' {
			line++
			lastBreak = i + 1
		}
	}
	return line, 1 + i - lastBreak
}

func (p *jsonParser) fail(message string) { p.failAt(message + " in JSON") }

// failAt appends V8's position suffix to message.
func (p *jsonParser) failAt(message string) {
	line, column := p.lineColumn()
	panic(&jsonError{fmt.Sprintf("%s at position %d (line %d column %d)", message, p.pos, line, column)})
}

// unexpected reports the character at p.pos as an unexpected token.
func (p *jsonParser) unexpected() {
	if p.pos >= len(p.src) {
		panic(&jsonError{"Unexpected end of JSON input"})
	}
	c := p.src[p.pos]
	switch {
	case c == '"':
		p.fail("Unexpected string")
	case c == '-' || (c >= '0' && c <= '9'):
		p.fail("Unexpected number")
	}
	source := fromUTF16(p.src)
	switch source {
	case "[object Object]", "undefined", "Infinity", "NaN":
		panic(&jsonError{fmt.Sprintf("\"%s\" is not valid JSON", source)})
	}
	token := fromUTF16(p.src[p.pos : p.pos+1])
	const maxContext = 10
	n := len(p.src)
	if n < maxContext*2+1 {
		panic(&jsonError{fmt.Sprintf("Unexpected token '%s', \"%s\" is not valid JSON", token, source)})
	}
	var message string
	switch {
	case p.pos < maxContext:
		message = fmt.Sprintf("Unexpected token '%s', \"%s\"... is not valid JSON", token, fromUTF16(p.src[:p.pos+maxContext]))
	case p.pos < n-maxContext:
		message = fmt.Sprintf("Unexpected token '%s', ...\"%s\"... is not valid JSON", token, fromUTF16(p.src[p.pos-maxContext:p.pos+maxContext]))
	default:
		message = fmt.Sprintf("Unexpected token '%s', ...\"%s\" is not valid JSON", token, fromUTF16(p.src[p.pos-maxContext:]))
	}
	panic(&jsonError{message})
}

func (p *jsonParser) peek() int {
	if p.pos >= len(p.src) {
		return -1
	}
	return int(p.src[p.pos])
}

func (p *jsonParser) parseValue() *value {
	switch c := p.peek(); {
	case c == '"':
		return strValue(p.parseString())
	case c == '-' || (c >= '0' && c <= '9'):
		return numValue(p.parseNumber())
	case c == 't':
		p.literal("true")
		return &value{k: kBool, b: true}
	case c == 'f':
		p.literal("false")
		return &value{k: kBool, b: false}
	case c == 'n':
		p.literal("null")
		return &value{k: kNull}
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	}
	p.unexpected()
	return nil
}

func (p *jsonParser) literal(word string) {
	p.pos++
	for i := 1; i < len(word); i++ {
		if p.pos >= len(p.src) {
			panic(&jsonError{"Unexpected end of JSON input"})
		}
		if p.src[p.pos] != uint16(word[i]) {
			p.unexpected()
		}
		p.pos++
	}
}

func isDigit(c int) bool { return c >= '0' && c <= '9' }

func (p *jsonParser) parseNumber() float64 {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
		if !isDigit(p.peek()) {
			p.fail("No number after minus sign")
		}
	}
	if p.peek() == '0' {
		p.pos++
		if isDigit(p.peek()) {
			p.unexpected()
		}
	} else {
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	if p.peek() == '.' {
		p.pos++
		if !isDigit(p.peek()) {
			p.fail("Unterminated fractional number")
		}
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		p.pos++
		if c := p.peek(); c == '+' || c == '-' {
			p.pos++
		}
		if !isDigit(p.peek()) {
			p.fail("Exponent part is missing a number")
		}
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	text := make([]byte, 0, p.pos-start)
	for _, u := range p.src[start:p.pos] {
		text = append(text, byte(u))
	}
	f, _ := strconv.ParseFloat(string(text), 64)
	return f
}

func hexValue(c int) int {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return -1
}

func (p *jsonParser) parseString() string {
	p.pos++ // opening quote
	var units []uint16
	for {
		if p.pos >= len(p.src) {
			p.fail("Unterminated string")
		}
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return fromUTF16(units)
		case c == '\\':
			p.pos++
			if p.pos >= len(p.src) {
				panic(&jsonError{"Unexpected end of JSON input"})
			}
			e := p.src[p.pos]
			switch e {
			case '"', '\\', '/':
				units = append(units, e)
			case 'b':
				units = append(units, '\b')
			case 'f':
				units = append(units, '\f')
			case 'n':
				units = append(units, '\n')
			case 'r':
				units = append(units, '\r')
			case 't':
				units = append(units, '\t')
			case 'u':
				code := 0
				for i := 0; i < 4; i++ {
					p.pos++
					h := hexValue(p.peek())
					if h < 0 {
						p.fail("Bad Unicode escape")
					}
					code = code*16 + h
				}
				units = append(units, uint16(code))
			default:
				p.fail("Bad escaped character")
			}
			p.pos++
		case c < 0x20:
			p.fail("Bad control character in string literal")
		default:
			units = append(units, c)
			p.pos++
		}
	}
}

func (p *jsonParser) parseObject() *value {
	obj := &object{vals: map[string]*value{}}
	p.pos++
	p.skipWS()
	if p.peek() == '}' {
		p.pos++
		return &value{k: kObj, obj: obj}
	}
	if p.peek() != '"' {
		p.fail("Expected property name or '}'")
	}
	for {
		key := p.parseString()
		p.skipWS()
		if p.peek() != ':' {
			p.fail("Expected ':' after property name")
		}
		p.pos++
		p.skipWS()
		v := p.parseValue()
		if _, ok := obj.vals[key]; !ok {
			obj.keys = append(obj.keys, key)
		}
		obj.vals[key] = v
		p.skipWS()
		switch p.peek() {
		case ',':
			p.pos++
			p.skipWS()
			if p.peek() != '"' {
				p.fail("Expected double-quoted property name")
			}
		case '}':
			p.pos++
			return &value{k: kObj, obj: obj}
		default:
			p.fail("Expected ',' or '}' after property value")
		}
	}
}

func (p *jsonParser) parseArray() *value {
	arr := &value{k: kArr, arr: []*value{}}
	p.pos++
	p.skipWS()
	if p.peek() == ']' {
		p.pos++
		return arr
	}
	for {
		p.skipWS()
		arr.arr = append(arr.arr, p.parseValue())
		p.skipWS()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return arr
		default:
			p.fail("Expected ',' or ']' after array element")
		}
	}
}

// ---------------------------------------------------------------------------
// Node's posix path helpers.

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

// ---------------------------------------------------------------------------
// File system helpers that report errors the way Node does.

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

// ---------------------------------------------------------------------------
// The triage logic, ported from tanx.ts.

type cli struct {
	sarif   string
	summary string
	logs    string
	hasLogs bool
}

type finding struct {
	severity string
	rule     *value
	file     string
	line     string
	message  string
}

type diagnostic struct {
	severity string
	source   *value
	message  string
}

var severityRank = map[string]int{
	"error":   0,
	"warning": 1,
	"note":    2,
	"none":    3,
}

var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"bin":          true,
	"obj":          true,
	"cache":        true,
	"trap":         true,
}

const usage = "Usage: cosx-vs-tanx-triage.go --sarif <file-or-dir> --summary <markdown> [--logs <dir>]\n"

func parseArgs(argv []string) cli {
	c := cli{
		sarif:   "codeql-results",
		summary: nodeJoin("codeql-results", "tanx-summary.md"),
	}
	if runnerTemp := os.Getenv("RUNNER_TEMP"); runnerTemp != "" {
		c.logs, c.hasLogs = nodeJoin(runnerTemp, "codeql_databases"), true
	}
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}
		switch {
		case arg == "--sarif" && next != "":
			c.sarif = next
			i++
		case arg == "--summary" && next != "":
			c.summary = next
			i++
		case arg == "--logs" && next != "":
			c.logs, c.hasLogs = next, true
			i++
		case arg == "--help" || arg == "-h":
			os.Stdout.WriteString(usage)
			os.Exit(0)
		default:
			throwError("Error", "Unknown argument: %s", arg)
		}
	}
	return c
}

const jsWS = `\t\n\x0B\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

var (
	reSpaceRun     = regexp.MustCompile(`[` + jsWS + `]+`)
	reNewline      = regexp.MustCompile(`\r?\n`)
	reDriveLetter  = regexp.MustCompile(`^/[A-Za-z]:`)
	reDiagRule     = regexp.MustCompile(`diagnostic|extractor|successfully-extracted`) // on asciiLower
	reExtracted    = regexp.MustCompile(`/diagnostics/successfully-extracted-files$`)
	reLinesOfCode  = regexp.MustCompile(`/summary/lines-of-code$`)
	reInterpreted  = regexp.MustCompile(`interpreted (diagnostic|problem|pathproblem|metric) query`)
	reDetails      = regexp.MustCompile(`\[details\]`)
	reColonLevel   = regexp.MustCompile(`:[` + jsWS + `]*(error|warning)[` + jsWS + `]`)
	reCompilerCode = regexp.MustCompile(`\b(error|warning)[` + jsWS + `]+(cs|msb)\d+`)
	reBuildOK      = regexp.MustCompile(`\bbuild succeeded\b`)
	reBuildFailed  = regexp.MustCompile(`\bbuild failed\b`)
	reCounts       = regexp.MustCompile(`\d+[` + jsWS + `]+(Error|Warning)\(s\)`)
	reNoSource     = regexp.MustCompile(`no source code (was )?seen`)
	reFailedToExt  = regexp.MustCompile(`failed to extract`)
	reBracketLevel = regexp.MustCompile(`\][` + jsWS + `]*(ERROR|WARNING)\b`)
	reSevError     = regexp.MustCompile(`error|failed|fatal`)
	reZeroErrors   = regexp.MustCompile(`0 Error\(s\)`)
	reSevWarning   = regexp.MustCompile(`warning`)
	reZeroWarnings = regexp.MustCompile(`0 Warning\(s\)`)
	reBuildMode    = regexp.MustCompile(`(?m)(?:^|[\r\x{2028}\x{2029}])buildMode:[` + jsWS + `]*([^` + jsWS + `]+)`)
	reLanguage     = regexp.MustCompile(`(?m)(?:^|[\r\x{2028}\x{2029}])primaryLanguage:[` + jsWS + `]*([^` + jsWS + `]+)`)
)

func messageText(message *value) string {
	text := coalesce(coalesce(opt(message, "text"), opt(message, "markdown")), strValue(""))
	return jsTrim(reSpaceRun.ReplaceAllString(requireString(text, "replace"), " "))
}

func cell(v *value) string {
	s := requireString(v, "replace")
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '`', '*', '_', '[', ']', '|':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return jsTrim(reNewline.ReplaceAllString(b.String(), " "))
}

func cellText(s string) string { return cell(strValue(s)) }

func rankOf(level string) int {
	if r, ok := severityRank[level]; ok {
		return r
	}
	return 4
}

func displayPath(uri string) string {
	path := jsTrim(uri)
	if strings.HasPrefix(path, "file://") {
		path = decodeURIComponent(path[len("file://"):])
		if reDriveLetter.MatchString(path) {
			path = path[1:]
		}
	}
	path = strings.ReplaceAll(path, "\\", "/")
	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" && strings.HasPrefix(path, "/") {
		rel := nodeRelative(nodeResolve(workspace), path)
		if rel != "" && !strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, "/") {
			return strings.ReplaceAll(rel, "\\", "/")
		}
	}
	return path
}

func locationOf(result *value) (string, string) {
	places := append([]*value{}, iterate(coalesce(get(result, "locations"), &value{k: kArr}), "result.locations")...)
	places = append(places, iterate(coalesce(get(result, "relatedLocations"), &value{k: kArr}), "result.relatedLocations")...)
	for _, place := range places {
		physical := get(place, "physicalLocation")
		uri := opt(opt(physical, "artifactLocation"), "uri")
		if !truthy(uri) {
			continue
		}
		line := opt(opt(physical, "region"), "startLine")
		lineText := ""
		if line.isNumber() && line.n > 0 {
			lineText = jsNumber(line.n)
		}
		return displayPath(requireString(uri, "trim")), lineText
	}
	return "(no location)", ""
}

type ruleMap map[string]*value

func rulesByID(run *value) ruleMap {
	rules := ruleMap{}
	tool := get(run, "tool")
	groups := []*value{coalesce(opt(opt(tool, "driver"), "rules"), &value{k: kArr})}
	for _, extension := range iterate(coalesce(opt(tool, "extensions"), &value{k: kArr}), "run.tool.extensions") {
		groups = append(groups, coalesce(get(extension, "rules"), &value{k: kArr}))
	}
	for _, group := range groups {
		for _, rule := range iterate(group, "group") {
			if id := get(rule, "id"); truthy(id) {
				rules[sameValueZeroKey(id)] = rule
			}
		}
	}
	return rules
}

func findingSeverity(result, rule *value) string {
	level := coalesce(coalesce(get(result, "level"), opt(opt(rule, "defaultConfiguration"), "level")), strValue("warning"))
	text := jsLower(requireString(level, "toLowerCase"))
	suppressions := get(result, "suppressions")
	if truthy(suppressions) {
		if n := get(suppressions, "length"); jsGreaterThanZero(n) {
			return text + " (suppressed)"
		}
	}
	return text
}

func jsGreaterThanZero(v *value) bool {
	if v.isString() {
		return stringToNumber(v.s) > 0
	}
	return toNumber(v) > 0
}

func isDiagnosticRule(ruleID *value) bool {
	return reDiagRule.MatchString(asciiLower(toStr(ruleID)))
}

func walk(root string, accept func(string) bool) []string {
	if !exists(root) {
		return nil
	}
	var found []string
	var visit func(current string, depth int)
	visit = func(current string, depth int) {
		if depth > 8 {
			return
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "db-") || skipDirs[name] {
				continue
			}
			full := nodeJoin(current, name)
			if e.IsDir() {
				visit(full, depth+1)
			} else if e.Type().IsRegular() && accept(name) {
				found = append(found, full)
			}
		}
	}
	info, err := os.Stat(root)
	if err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "stat", root))
	}
	if info.Mode().IsRegular() {
		if accept(nodeBasename(root)) {
			found = append(found, root)
		}
		return found
	}
	visit(root, 0)
	return found
}

func readCapped(path string, maxBytes int64) string {
	info, err := os.Stat(path)
	if err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "stat", path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "open", path))
	}
	if size := info.Size(); size > maxBytes {
		start := size - maxBytes
		if start > int64(len(data)) {
			data = nil
		} else {
			data = data[start:]
		}
	}
	return fromUTF16(decodeUTF8(data))
}

func interestingLogLine(line string) bool {
	if utf16Len(line) > 500 {
		return false
	}
	lower := asciiLower(line)
	// CodeQL's own query-evaluation log names queries such as "Extraction error"
	// while describing a successful run. Those lines are not build failures.
	if reInterpreted.MatchString(lower) {
		return false
	}
	if reDetails.MatchString(lower) {
		return false
	}
	return reColonLevel.MatchString(lower) ||
		reCompilerCode.MatchString(lower) ||
		reBuildOK.MatchString(lower) ||
		reBuildFailed.MatchString(lower) ||
		reCounts.MatchString(line) ||
		reNoSource.MatchString(lower) ||
		reFailedToExt.MatchString(lower) ||
		reBracketLevel.MatchString(line)
}

func logDiagnostics(path string) []diagnostic {
	text := readCapped(path, 1_000_000)
	source := strValue(nodeBasename(path))
	var lines []string
	for _, raw := range strings.Split(text, "\n") {
		line := jsTrim(raw)
		if interestingLogLine(line) {
			lines = append(lines, line)
		}
	}
	var unique []string
	for _, line := range lines {
		if len(unique) == 0 || unique[len(unique)-1] != line {
			unique = append(unique, line)
		}
	}
	if len(unique) > 40 {
		unique = unique[:40]
	}
	out := make([]diagnostic, 0, len(unique))
	for _, line := range unique {
		lower := asciiLower(line)
		severity := "note"
		if reSevError.MatchString(lower) && !reZeroErrors.MatchString(line) {
			severity = "error"
		} else if reSevWarning.MatchString(lower) && !reZeroWarnings.MatchString(line) {
			severity = "warning"
		}
		if reBuildOK.MatchString(lower) {
			severity = "note"
		}
		out = append(out, diagnostic{severity: severity, source: source, message: line})
	}
	return out
}

func databaseNotes(root string) []string {
	var notes []string
	for _, path := range walk(root, func(name string) bool { return name == "codeql-database.yml" }) {
		text := readCapped(path, 100_000)
		parts := []string{nodeBasename(nodeDirname(path))}
		if m := reLanguage.FindStringSubmatch(text); m != nil {
			parts = append(parts, "language="+m[1])
		}
		if m := reBuildMode.FindStringSubmatch(text); m != nil {
			parts = append(parts, "buildMode="+m[1])
		}
		notes = append(notes, strings.Join(parts, " "))
	}
	return notes
}

func stringifyShort(v *value) string {
	switch v.k {
	case kStr:
		return v.s
	case kNum, kBool:
		return toStr(v)
	}
	text := stringify(v)
	if units := toUTF16(text); len(units) > 240 {
		return fromUTF16(units[:237]) + "..."
	}
	return text
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

type summaryResult struct {
	markdown        string
	findingCount    int
	diagnosticCount int
	analysisOk      bool
}

func summarize(c cli) summaryResult {
	sarifPaths := walk(c.sarif, func(name string) bool {
		return strings.HasSuffix(name, ".sarif") || strings.HasSuffix(name, ".sarif.json")
	})
	logPaths := walk(c.sarif, func(name string) bool { return strings.HasSuffix(name, ".log") })
	if c.hasLogs {
		logPaths = append(logPaths, walk(c.logs, func(name string) bool {
			return strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".txt")
		})...)
	}
	var findings []finding
	var diagnostics []diagnostic
	var tools []*value
	var linesOfCode *float64
	unreadableSarif := 0
	tanx := strValue("tanx")

	if !exists(c.sarif) {
		diagnostics = append(diagnostics, diagnostic{"error", tanx, "SARIF path does not exist: " + c.sarif})
	} else if len(sarifPaths) == 0 {
		diagnostics = append(diagnostics, diagnostic{"error", tanx, "No SARIF files were produced. Analysis stopped before CodeQL wrote results."})
	}

	for _, path := range sarifPaths {
		data, err := os.ReadFile(path)
		var parsed *value
		if err != nil {
			err = errors.New(nodeFsMessage(err, "open", path))
		} else {
			units := decodeUTF8(data)
			if len(units) > 0 && units[0] == 0xFEFF {
				units = units[1:]
			}
			parsed, err = parseJSON(units)
		}
		if err != nil {
			unreadableSarif++
			diagnostics = append(diagnostics, diagnostic{"error", strValue(nodeBasename(path)), "Could not parse SARIF: " + err.Error()})
			continue
		}
		for _, run := range iterate(coalesce(get(parsed, "runs"), &value{k: kArr}), "parsed.runs") {
			driver := opt(get(run, "tool"), "driver")
			toolName := or(or(opt(driver, "fullName"), opt(driver, "name")), strValue("CodeQL"))
			if semver := opt(driver, "semanticVersion"); truthy(semver) {
				tools = append(tools, strValue(toStr(toolName)+" "+toStr(get(driver, "semanticVersion"))))
			} else {
				tools = append(tools, toolName)
			}
			rules := rulesByID(run)
			for _, invocation := range iterate(coalesce(get(run, "invocations"), &value{k: kArr}), "run.invocations") {
				if ok := get(invocation, "executionSuccessful"); ok != nil && ok.k == kBool && !ok.b {
					exit := ""
					if code := get(invocation, "exitCode"); !code.isUndef() {
						exit = " (exit " + toStr(code) + ")"
					}
					diagnostics = append(diagnostics, diagnostic{"error", strValue(nodeBasename(path)), "CodeQL invocation failed" + exit + "."})
				}
				notifications := append([]*value{}, iterate(coalesce(get(invocation, "toolExecutionNotifications"), &value{k: kArr}), "toolExecutionNotifications")...)
				notifications = append(notifications, iterate(coalesce(get(invocation, "toolConfigurationNotifications"), &value{k: kArr}), "toolConfigurationNotifications")...)
				var extractedFiles []string
				for _, notification := range notifications {
					source := coalesce(opt(get(notification, "descriptor"), "id"), strValue(nodeBasename(path)))
					uri := opt(opt(opt(opt(get(notification, "locations"), "0"), "physicalLocation"), "artifactLocation"), "uri")
					file := ""
					if truthy(uri) {
						file = displayPath(requireString(uri, "trim"))
					}
					if reExtracted.MatchString(toStr(source)) && file != "" {
						extractedFiles = append(extractedFiles, file)
						continue
					}
					text := messageText(get(notification, "message"))
					attributes := opt(get(notification, "properties"), "attributes")
					attributeText := ""
					if truthy(attributes) {
						var parts []string
						for _, e := range entries(attributes) {
							parts = append(parts, e.key+"="+stringifyShort(e.val))
						}
						attributeText = strings.Join(parts, ", ")
					}
					var kept []string
					for _, part := range []string{text, file, attributeText} {
						if part != "" {
							kept = append(kept, part)
						}
					}
					message := strings.Join(kept, " ")
					severity := jsLower(requireString(coalesce(get(notification, "level"), strValue("warning")), "toLowerCase"))
					if (severity == "none" || severity == "") && message != "" {
						severity = "note"
					}
					if message == "" {
						continue
					}
					diagnostics = append(diagnostics, diagnostic{severity, source, message})
				}
				if len(extractedFiles) > 0 {
					sort.SliceStable(extractedFiles, func(i, j int) bool { return compareUTF16(extractedFiles[i], extractedFiles[j]) })
					diagnostics = append(diagnostics, diagnostic{
						"note",
						strValue("diagnostics/successfully-extracted-files"),
						fmt.Sprintf("Extracted %d files: %s", len(extractedFiles), strings.Join(extractedFiles, ", ")),
					})
				}
			}
			metrics := opt(get(run, "properties"), "metricResults")
			if metrics != nil && metrics.k == kArr {
				for _, metric := range metrics.arr {
					if !truthy(metric) || !metric.isObjLike() {
						continue
					}
					ruleID := get(metric, "ruleId")
					v := get(metric, "value")
					if ruleID.isString() && reLinesOfCode.MatchString(ruleID.s) && v.isNumber() {
						n := v.n
						linesOfCode = &n
					}
				}
			}
			for _, result := range iterate(coalesce(get(run, "results"), &value{k: kArr}), "run.results") {
				ruleID := or(or(get(result, "ruleId"), opt(get(result, "rule"), "id")), strValue("(no rule)"))
				rule := rules[sameValueZeroKey(ruleID)]
				severity := findingSeverity(result, rule)
				message := messageText(get(result, "message"))
				if message == "" {
					message = messageText(opt(rule, "shortDescription"))
				}
				if message == "" {
					message = "(no message)"
				}
				file, line := locationOf(result)
				if isDiagnosticRule(ruleID) {
					text := file + " " + message
					if line != "" {
						text = file + ":" + line + " " + message
					}
					diagnostics = append(diagnostics, diagnostic{strings.Replace(severity, " (suppressed)", "", 1), ruleID, text})
				} else {
					findings = append(findings, finding{severity, ruleID, file, line, message})
				}
			}
		}
	}

	for _, path := range logPaths {
		diagnostics = append(diagnostics, logDiagnostics(path)...)
	}

	var dbNotes []string
	if c.hasLogs && exists(c.logs) {
		dbNotes = databaseNotes(c.logs)
	}
	if c.hasLogs && !exists(c.logs) {
		diagnostics = append(diagnostics, diagnostic{"note", tanx, "CodeQL database log directory was not found: " + c.logs})
	}

	lineNumber := func(line string) float64 {
		if line == "" {
			return 0
		}
		return stringToNumber(line)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if rank := rankOf(a.severity) - rankOf(b.severity); rank != 0 {
			return rank < 0
		}
		if f := localeCompare(a.file, b.file); f != 0 {
			return f < 0
		}
		return lineNumber(a.line)-lineNumber(b.line) < 0
	})

	var countOrder []string
	counts := map[string]int{}
	for _, f := range findings {
		key := strings.Replace(f.severity, " (suppressed)", "", 1)
		if _, ok := counts[key]; !ok {
			countOrder = append(countOrder, key)
		}
		counts[key]++
	}
	var countParts []string
	for _, level := range countOrder {
		countParts = append(countParts, fmt.Sprintf("%d %s", counts[level], level))
	}
	countText := strings.Join(countParts, ", ")

	var lines []string
	push := func(s string) { lines = append(lines, s) }
	push("## cosx-vs-tanx-triage")
	push("")
	push("### Analysis")
	push("")
	analysisOk := len(sarifPaths) > 0 && unreadableSarif == 0
	if analysisOk {
		push("- Analysis status: completed")
	} else {
		push("- Analysis status: FAILED (results missing or unreadable)")
	}
	push(fmt.Sprintf("- SARIF files: %d", len(sarifPaths)))
	if len(tools) > 0 {
		seen := map[string]bool{}
		var uniqueTools []string
		for _, t := range tools {
			key := sameValueZeroKey(t)
			if seen[key] {
				continue
			}
			seen[key] = true
			uniqueTools = append(uniqueTools, toStr(t))
		}
		push("- Tool: " + strings.Join(uniqueTools, ", "))
	}
	if countText != "" {
		push(fmt.Sprintf("- Findings: %d (%s)", len(findings), countText))
	} else {
		push(fmt.Sprintf("- Findings: %d", len(findings)))
	}
	if linesOfCode != nil {
		push("- Lines of code extracted: " + jsNumber(*linesOfCode))
	}
	if len(dbNotes) > 0 {
		push("- Database: " + strings.Join(dbNotes, "; "))
	}
	push("")
	push("### Findings")
	push("")
	switch {
	case !analysisOk:
		push("Analysis did not complete, so this is NOT a clean result. See extraction and build.")
	case len(findings) == 0:
		push("CodeQL reported no findings.")
	default:
		push("| Severity | Rule | Location | Message |")
		push("| --- | --- | --- | --- |")
		for _, f := range findings {
			location := f.file
			if f.line != "" {
				location = f.file + ":" + f.line
			}
			push(fmt.Sprintf("| %s | %s | %s | %s |", cellText(f.severity), cell(f.rule), cellText(location), cellText(f.message)))
		}
	}
	push("")
	push("### Extraction and build")
	push("")
	if len(diagnostics) == 0 {
		push("No extraction or build errors or warnings were recorded.")
	} else {
		shown := diagnostics
		if len(shown) > 60 {
			shown = shown[:60]
		}
		push("| Severity | Source | Message |")
		push("| --- | --- | --- |")
		for _, d := range shown {
			push(fmt.Sprintf("| %s | %s | %s |", cellText(d.severity), cell(d.source), cellText(d.message)))
		}
		if len(diagnostics) > len(shown) {
			push("")
			push(fmt.Sprintf("Showing %d of %d diagnostic lines.", len(shown), len(diagnostics)))
		}
	}
	push("")

	return summaryResult{
		markdown:        strings.Join(lines, "\n") + "\n",
		findingCount:    len(findings),
		diagnosticCount: len(diagnostics),
		analysisOk:      analysisOk,
	}
}

func run() int {
	c := parseArgs(os.Args[1:])
	result := summarize(c)
	markdown := toOutput(result.markdown)
	dir := nodeDirname(nodeResolve(c.summary))
	if err := os.MkdirAll(dir, 0o777); err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "mkdir", dir))
	}
	if err := os.WriteFile(c.summary, []byte(markdown), 0o666); err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "open", c.summary))
	}
	if stepSummary := os.Getenv("GITHUB_STEP_SUMMARY"); stepSummary != "" {
		f, err := os.OpenFile(stepSummary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
		if err == nil {
			_, err = f.WriteString(markdown)
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
		}
		if err != nil {
			throwError("Error", "%s", nodeFsMessage(err, "open", stepSummary))
		}
	}
	os.Stdout.WriteString(markdown)
	fmt.Fprintf(os.Stdout, "tanx: %d finding(s), %d diagnostic line(s)\n", result.findingCount, result.diagnosticCount)
	if !result.analysisOk {
		return 2
	}
	return 0
}

func main() {
	code := func() (code int) {
		defer func() {
			if r := recover(); r != nil {
				je, ok := r.(*jsError)
				if !ok {
					panic(r)
				}
				fmt.Fprintf(os.Stderr, "%s: %s\n", je.name, je.message)
				code = 1
			}
		}()
		return run()
	}()
	os.Exit(code)
}
