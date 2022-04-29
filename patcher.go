package yamlpatch

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/yamlpatch/internal/merge"
	"github.com/pkg/errors"

	"gopkg.in/yaml.v2"
)

type Patcher struct {
	BaseFilePath  string
	PatchFilePath string
}

func NewPatcher(filePath string) *Patcher {
	yamlpatcher := Patcher{
		BaseFilePath:  filePath,
		PatchFilePath: filePath + ".patch",
	}

	return &yamlpatcher
}

// read a single YAML file, check for errors (the merge package doesn't) then return the content as bytes
func readYAML(filePath string) ([]byte, error) {
	var yamlMap map[interface{}]interface{}
	var content []byte
	var err error

	if content, err = os.ReadFile(filePath); err != nil {
		return nil, err
	}

	if err = yaml.Unmarshal(content, &yamlMap); err != nil {
		return nil, errors.Wrap(err, filePath)
	}

	return content, nil
}

// PatchedContent reads a YAML file and, if it exists, its '.patch' file, then
// merges them and returns it serialized
func (p *Patcher) PatchedContent() ([]byte, error) {
	var err error

	var base []byte
	base, err = readYAML(p.BaseFilePath)
	if err != nil {
		return nil, err
	}

	var over []byte
	over, err = readYAML(p.PatchFilePath)
	if err != nil {
		// optional file, ignore if it does not exist
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	} else {
		log.Debugf("Patching yaml: '%s' with '%s'", p.BaseFilePath, p.PatchFilePath)
	}

	sourceBytes := [][]byte{base, over}

	patched, err := merge.YAML(sourceBytes, true)
	if err != nil {
		return nil, err
	}

	return patched.Bytes(), nil
}
