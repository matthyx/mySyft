package main

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func main() {
	imageHash := "library/nginx@sha256:b8f2383a95879e1ae064940d9a200f67a6c79e710ed82ac42263397367e7cc4e"
	userInput := "registry:" + imageHash
	sourceInput, err := source.ParseInput(userInput, "", true)
	if err != nil {
		panic(err)
	}
	registryOptions := &image.RegistryOptions{
		InsecureSkipTLSVerify: false,
		InsecureUseHTTP:       false,
		Credentials:           nil,
		Platform:              "",
	}
	// download image
	src, cleanup, err := source.New(*sourceInput, registryOptions, []string{})
	defer cleanup()
	if err != nil {
		panic(err)
	}
	// extract packages
	catalogOptions := cataloger.Config{
		Search: cataloger.DefaultSearchConfig(),
	}
	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(src, catalogOptions)
	if err != nil {
		panic(err)
	}
	// generate SBOM
	s := sbom.SBOM{
		Source:        src.Metadata,
		Relationships: relationships,
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkgCatalog,
			LinuxDistribution: actualDistro,
		},
	}
	// save SBOM
	writerOptions := sbom.WriterOption{
		Format: spdxjson.Format(),
		Path:   "sbom.json",
	}
	writer, err := sbom.NewWriter(writerOptions)
	if err != nil {
		panic(err)
	}
	err = writer.Write(s)
	if err != nil {
		panic(err)
	}
}
