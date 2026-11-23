package main

// docs/json-schema.md is the contract users program against, so it is checked by
// a test rather than trusted. The check is bidirectional: a field in the code
// that the document does not mention is a field no consumer can learn about, and
// a field in the document that the code does not emit is a promise the tool
// cannot keep. Both make the document useless, in opposite directions.

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// schemaDocPath is relative to this package, which is where `go test` runs.
const schemaDocPath = "../../docs/json-schema.md"

// docRoots are the three documents the CLI can print. A root is not expanded
// inside another document (bothReport names its two halves), because each root
// has its own section and a repeated expansion would report every port field
// twice.
var docRoots = map[string]reflect.Type{
	"portReport": reflect.TypeOf(portReport{}),
	"unixReport": reflect.TypeOf(unixReport{}),
	"bothReport": reflect.TypeOf(bothReport{}),
}

// schemaField is one path in one document, with the JSON type a consumer sees.
type schemaField struct {
	Path string
	Type string
}

// walkSchema lists every path below t, using the same notation the document
// uses: "." between object members and "[]" for an array's element.
func walkSchema(t reflect.Type, prefix string, out *[]schemaField) {
	switch t.Kind() {
	case reflect.Struct:
		if _, isRoot := docRoots[t.Name()]; isRoot && prefix != "" {
			// A nested document is described by its own section.
			*out = append(*out, schemaField{Path: prefix, Type: "object"})
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			walkSchema(f.Type, path, out)
		}
	case reflect.Pointer:
		elem := t.Elem()
		path := prefix
		if elem.Kind() != reflect.Struct {
			// A pointer scalar is how this document spells "measured or absent",
			// so the null is part of the type a consumer has to handle.
			*out = append(*out, schemaField{Path: path, Type: jsonTypeName(elem) + "|null"})
			return
		}
		walkSchema(elem, path, out)
	case reflect.Slice:
		elem := t.Elem()
		if elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct {
			walkSchema(elem, prefix+"[]", out)
			return
		}
		*out = append(*out, schemaField{Path: prefix + "[]", Type: jsonTypeName(elem)})
	default:
		*out = append(*out, schemaField{Path: prefix, Type: jsonTypeName(t)})
	}
}

func jsonTypeName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int64, reflect.Uint64:
		return "integer"
	case reflect.Slice:
		return "array"
	default:
		return t.Kind().String()
	}
}

// readSchemaDoc returns section name → the field paths listed under it.
//
// A missing or unreadable document fails the test: a gate that skips itself when
// its input is gone would report "the document agrees with the code" about a
// document that is not there.
func readSchemaDoc(t *testing.T) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(schemaDocPath))
	if err != nil {
		t.Fatalf("cannot read %s: %v (the gate must not skip: an absent schema is a broken schema)", schemaDocPath, err)
	}
	sections := map[string][]string{}
	current := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if rest, ok := strings.CutPrefix(line, "### "); ok {
			current = strings.TrimSpace(rest)
			if _, exists := sections[current]; !exists {
				sections[current] = nil
			}
			continue
		}
		if current == "" || !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 2 {
			continue
		}
		cell := strings.TrimSpace(cells[1])
		name, ok := strings.CutPrefix(cell, "`")
		if !ok {
			continue
		}
		name, ok = strings.CutSuffix(name, "`")
		if !ok || name == "" {
			continue
		}
		sections[current] = append(sections[current], name)
	}
	if len(sections) == 0 {
		t.Fatalf("%s lists no sections; the gate would pass against an empty file", schemaDocPath)
	}
	return sections
}

// TestJSONSchemaDocumentMatchesTheTypes is the gate itself.
func TestJSONSchemaDocumentMatchesTheTypes(t *testing.T) {
	sections := readSchemaDoc(t)

	for _, name := range sortedKeys(docRoots) {
		docPaths, ok := sections[name]
		if !ok {
			t.Errorf("docs/json-schema.md has no section ### %s", name)
			continue
		}
		var fields []schemaField
		walkSchema(docRoots[name], "", &fields)

		documented := map[string]bool{}
		for _, p := range docPaths {
			documented[p] = true
		}
		emitted := map[string]bool{}
		for _, f := range fields {
			emitted[f.Path] = true
			if !documented[f.Path] {
				t.Errorf("%s: field %q exists in the code and not in docs/json-schema.md", name, f.Path)
			}
		}
		for _, p := range docPaths {
			if !emitted[p] {
				t.Errorf("%s: docs/json-schema.md documents %q, which the code does not emit", name, p)
			}
		}
	}

	// A section for a type that is not a document is the same kind of lie as a
	// documented field that does not exist.
	for name := range sections {
		if _, known := docRoots[name]; !known {
			t.Errorf("docs/json-schema.md has a section ### %s, which is not a report type", name)
		}
	}
}

func sortedKeys(m map[string]reflect.Type) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
