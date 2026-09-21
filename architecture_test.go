package architecture_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "iwut-auth-center"

// TestArchitectureBoundaries keeps domain, port and use-case code independent
// from transport, configuration, concrete adapters and database drivers.
func TestArchitectureBoundaries(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	err := filepath.WalkDir(root+"/internal", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if len(parts) < 4 || (parts[2] != "domain" && parts[2] != "port" && parts[2] != "usecase") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if reason := forbiddenCoreImport(parts[2], importPath); reason != "" {
				t.Errorf("%s imports %s: %s", filepath.ToSlash(relative), importPath, reason)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal packages: %v", err)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate architecture test")
	}
	return filepath.Dir(filename)
}

func forbiddenCoreImport(layer, importPath string) string {
	if strings.HasPrefix(importPath, modulePath+"/internal/adapter") ||
		strings.HasPrefix(importPath, modulePath+"/internal/config") {
		return "core layers cannot depend on adapters or configuration"
	}
	if strings.Contains(importPath, "mongo") || strings.HasPrefix(importPath, "database/") ||
		strings.HasPrefix(importPath, "net/http") || strings.HasPrefix(importPath, "google.golang.org/grpc") ||
		strings.HasPrefix(importPath, "github.com/go-kratos/") {
		return "core layers cannot depend on storage or transport libraries"
	}
	if layer == "domain" && strings.HasPrefix(importPath, modulePath+"/internal/") {
		return "domain is a dependency leaf"
	}
	return ""
}
