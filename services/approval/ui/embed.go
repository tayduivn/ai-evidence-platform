package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var embeddedAssets embed.FS

// AssetHandler returns an http.Handler that serves the embedded web files.
func AssetHandler() http.Handler {
	subFS, err := fs.Sub(embeddedAssets, "web")
	if err != nil {
		panic("failed to locate embedded web directory: " + err.Error())
	}
	return http.FileServer(http.FS(subFS))
}
