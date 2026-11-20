// JSON.parse, including V8's error messages.

package main

import (
	"errors"
	"fmt"
	"strconv"
)

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
