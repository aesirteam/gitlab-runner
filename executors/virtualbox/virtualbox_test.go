package virtualbox_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/gitlab-org/gitlab-runner/common"
	"gitlab.com/gitlab-org/gitlab-runner/common/buildtest"
	"gitlab.com/gitlab-org/gitlab-runner/helpers"
	"gitlab.com/gitlab-org/gitlab-runner/helpers/ssh"
)

const vboxImage = "ubuntu-runner"
const vboxManage = "vboxmanage"

var vboxSSHConfig = &ssh.Config{
	User:     "vagrant",
	Password: "vagrant",
}

func TestVirtualBoxExecutorRegistered(t *testing.T) {
	executorNames := common.GetExecutorNames()
	assert.Contains(t, executorNames, "virtualbox")
}

func TestVirtualBoxCreateExecutor(t *testing.T) {
	executor := common.NewExecutor("virtualbox")
	assert.NotNil(t, executor)
}

func TestVirtualBoxSuccessRun(t *testing.T) {
	if helpers.SkipIntegrationTests(t, vboxManage, "--version") {
		return
	}

	successfulBuild, err := common.GetRemoteSuccessfulBuild()
	assert.NoError(t, err)
	build := &common.Build{
		JobResponse: successfulBuild,
		Runner: &common.RunnerConfig{
			RunnerSettings: common.RunnerSettings{
				Executor: "virtualbox",
				VirtualBox: &common.VirtualBoxConfig{
					BaseName:         vboxImage,
					DisableSnapshots: true,
				},
				SSH: vboxSSHConfig,
			},
		},
	}

	err = build.Run(&common.Config{}, &common.Trace{Writer: os.Stdout})
	assert.NoError(t, err, "Make sure that you have done 'make development_setup'")
}

func TestVirtualBoxSuccessRunRawVariable(t *testing.T) {
	if helpers.SkipIntegrationTests(t, vboxManage, "--version") {
		return
	}

	successfulBuild, err := common.GetRemoteBuildResponse("echo $TEST")
	assert.NoError(t, err)
	build := &common.Build{
		JobResponse: successfulBuild,
		Runner: &common.RunnerConfig{
			RunnerSettings: common.RunnerSettings{
				Executor: "virtualbox",
				VirtualBox: &common.VirtualBoxConfig{
					BaseName:         vboxImage,
					DisableSnapshots: true,
				},
				SSH: vboxSSHConfig,
			},
		},
	}

	value := "$VARIABLE$WITH$DOLLARS$$"
	build.Variables = append(build.Variables, common.JobVariable{
		Key:   "TEST",
		Value: value,
		Raw:   true,
	})

	out, err := buildtest.RunBuildReturningOutput(t, build)
	require.NoError(t, err, "Make sure that you have done 'make development_setup'")
	assert.Contains(t, out, value)
}

func TestVirtualBoxBuildFail(t *testing.T) {
	if helpers.SkipIntegrationTests(t, vboxManage, "--version") {
		return
	}

	failedBuild, err := common.GetRemoteFailedBuild()
	assert.NoError(t, err)
	build := &common.Build{
		JobResponse: failedBuild,
		Runner: &common.RunnerConfig{
			RunnerSettings: common.RunnerSettings{
				Executor: "virtualbox",
				VirtualBox: &common.VirtualBoxConfig{
					BaseName:         vboxImage,
					DisableSnapshots: true,
				},
				SSH: vboxSSHConfig,
			},
		},
	}

	err = build.Run(&common.Config{}, &common.Trace{Writer: os.Stdout})
	require.Error(t, err, "error")
	assert.IsType(t, &common.BuildError{}, err)
	assert.Contains(t, err.Error(), "Process exited with status 1")
}

func TestVirtualBoxMissingImage(t *testing.T) {
	if helpers.SkipIntegrationTests(t, vboxManage, "--version") {
		return
	}

	build := &common.Build{
		Runner: &common.RunnerConfig{
			RunnerSettings: common.RunnerSettings{
				Executor: "virtualbox",
				VirtualBox: &common.VirtualBoxConfig{
					BaseName:         "non-existing-image",
					DisableSnapshots: true,
				},
				SSH: vboxSSHConfig,
			},
		},
	}

	err := build.Run(&common.Config{}, &common.Trace{Writer: os.Stdout})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Could not find a registered machine named")
}

func TestVirtualBoxMissingSSHCredentials(t *testing.T) {
	if helpers.SkipIntegrationTests(t, vboxManage, "--version") {
		return
	}

	build := &common.Build{
		Runner: &common.RunnerConfig{
			RunnerSettings: common.RunnerSettings{
				Executor: "virtualbox",
				VirtualBox: &common.VirtualBoxConfig{
					BaseName:         "non-existing-image",
					DisableSnapshots: true,
				},
			},
		},
	}

	err := build.Run(&common.Config{}, &common.Trace{Writer: os.Stdout})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing SSH config")
}

func TestVirtualBoxBuildCancel(t *testing.T) {
	if helpers.SkipIntegrationTests(t, vboxManage, "--version") {
		return
	}

	config := &common.RunnerConfig{
		RunnerSettings: common.RunnerSettings{
			Executor: "virtualbox",
			VirtualBox: &common.VirtualBoxConfig{
				BaseName:         vboxImage,
				DisableSnapshots: true,
			},
			SSH: vboxSSHConfig,
		},
	}

	buildtest.RunBuildWithCancel(t, config, nil)
}
