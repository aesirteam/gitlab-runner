package process

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetProcessGroup(t *testing.T) {
	cmd := exec.Command("sleep", "1")
	require.Nil(t, cmd.SysProcAttr)
	setProcessGroup(cmd)
	assert.Nil(t, cmd.SysProcAttr)
}
