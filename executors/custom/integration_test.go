package custom_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/gitlab-org/gitlab-runner/common"
	"gitlab.com/gitlab-org/gitlab-runner/common/buildtest"
	"gitlab.com/gitlab-org/gitlab-runner/executors/custom/command"
	"gitlab.com/gitlab-org/gitlab-runner/helpers"
	"gitlab.com/gitlab-org/gitlab-runner/session"
	"gitlab.com/gitlab-org/gitlab-runner/shells/shellstest"
)

var testExecutorFile string

func TestMain(m *testing.M) {
	fmt.Println("Compiling test executor")

	curDir, err := os.Getwd()
	if err != nil {
		panic("Error on getting the working directory")
	}

	sourcesDir := filepath.Join(curDir, "testdata", "test_executor")
	sourcesFile := filepath.Join(sourcesDir, "main.go")

	targetDir, err := ioutil.TempDir("", "test_executor")
	if err != nil {
		panic("Error on preparing tmp directory for test executor binary")
	}
	testExecutorFile = filepath.Join(targetDir, "main")

	if runtime.GOOS == "windows" {
		// Adding it here, explicitly, in if, to show that this OS
		// requires a special treatment...
		testExecutorFile += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", testExecutorFile, sourcesFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Executing: %v", cmd)
	fmt.Println()

	err = cmd.Run()
	if err != nil {
		panic("Error on executing go build to prepare test custom executor")
	}

	code := m.Run()
	os.Exit(code)
}

func newBuild(t *testing.T, jobResponse common.JobResponse, shell string) (*common.Build, func()) {
	dir, err := ioutil.TempDir("", "gitlab-runner-custom-executor-test")
	require.NoError(t, err)

	t.Log("Build directory:", dir)

	build := &common.Build{
		JobResponse: jobResponse,
		Runner: &common.RunnerConfig{
			RunnerSettings: common.RunnerSettings{
				BuildsDir: filepath.Join(dir, "builds"),
				CacheDir:  filepath.Join(dir, "cache"),
				Executor:  "custom",
				Shell:     shell,
				Custom: &common.CustomConfig{
					ConfigExec:          testExecutorFile,
					ConfigArgs:          []string{shell, "config"},
					PrepareExec:         testExecutorFile,
					PrepareArgs:         []string{shell, "prepare"},
					RunExec:             testExecutorFile,
					RunArgs:             []string{shell, "run"},
					CleanupExec:         testExecutorFile,
					CleanupArgs:         []string{shell, "cleanup"},
					GracefulKillTimeout: timeoutInSeconds(10 * time.Second),
					ForceKillTimeout:    timeoutInSeconds(10 * time.Second),
				},
			},
		},
		SystemInterrupt: make(chan os.Signal, 1),
		Session: &session.Session{
			DisconnectCh: make(chan error),
			TimeoutCh:    make(chan error),
		},
	}

	cleanup := func() {
		_ = os.RemoveAll(dir)
	}

	return build, cleanup
}

func timeoutInSeconds(duration time.Duration) *int {
	seconds := duration.Seconds()
	secondsInInt := int(seconds)

	return &secondsInInt
}

func TestBuildSuccess(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		err = buildtest.RunBuild(t, build)
		assert.NoError(t, err)
	})
}

func TestBuildSuccessRawVariable(t *testing.T) {
	tests := map[string]struct {
		command string
	}{
		"bash": {
			command: "echo $TEST",
		},
		"powershell": {
			command: "echo $env:TEST",
		},
		"pwsh": {
			command: "echo $env:TEST",
		},
	}

	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		test, ok := tests[shell]
		if !ok {
			t.Skip()
		}

		successfulBuild, err := common.GetRemoteBuildResponse(test.command)
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		value := "$VARIABLE$WITH$DOLLARS$$"
		build.Variables = append(build.Variables, common.JobVariable{
			Key:   "TEST",
			Value: value,
			Raw:   true,
		})

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, value)
	})
}

func TestBuildBuildFailure(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Variables = append(build.Variables, common.JobVariable{
			Key:    "IS_BUILD_ERROR",
			Value:  "true",
			Public: true,
		})

		err = buildtest.RunBuild(t, build)
		assert.Error(t, err)
		var buildErr *common.BuildError
		assert.True(t, errors.As(err, &buildErr), "expected %T, got %T", buildErr, err)
	})
}

func TestBuildSystemFailure(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Variables = append(build.Variables, common.JobVariable{
			Key:    "IS_SYSTEM_ERROR",
			Value:  "true",
			Public: true,
		})

		err = buildtest.RunBuild(t, build)
		assert.Error(t, err)
		var exitError *exec.ExitError
		assert.True(t, errors.As(err, &exitError), "expected %T, got %T", exitError, err)
		t.Log(err)
	})
}

func TestBuildUnknownFailure(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Variables = append(build.Variables, common.JobVariable{
			Key:    "IS_UNKNOWN_ERROR",
			Value:  "true",
			Public: true,
		})

		err = buildtest.RunBuild(t, build)
		assert.Error(t, err)
		var errUnknownFailure *command.ErrUnknownFailure
		assert.True(t, errors.As(err, &errUnknownFailure), "expected %T, got %T", errUnknownFailure, err)
	})
}

func TestBuildCancel(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		build, cleanup := newBuild(t, common.JobResponse{}, shell)
		defer cleanup()

		updateSleepForCMD := func(build *common.Build) {
			if shell != "cmd" {
				return
			}

			resp, err := common.GetRemoteLongRunningBuildWithAfterScriptCMD()
			require.NoError(t, err)

			build.JobResponse = resp
		}

		buildtest.RunBuildWithCancel(t, build.Runner, updateSleepForCMD)
	})
}

func TestBuildWithGitStrategyCloneWithoutLFS(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Runner.PreCloneScript = "echo pre-clone-script"
		build.Variables = append(build.Variables, common.JobVariable{Key: "GIT_STRATEGY", Value: "clone"})

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Created fresh repository")

		out, err = buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Created fresh repository")
		assert.Regexp(t, "Checking out [a-f0-9]+ as", out)
		assert.Contains(t, out, "pre-clone-script")
	})
}

func TestBuildWithGitStrategyCloneNoCheckoutWithoutLFS(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Runner.PreCloneScript = "echo pre-clone-script"
		build.Variables = append(
			build.Variables,
			common.JobVariable{Key: "GIT_STRATEGY", Value: "clone"},
			common.JobVariable{Key: "GIT_CHECKOUT", Value: "false"},
		)

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Created fresh repository")

		out, err = buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Created fresh repository")
		assert.Contains(t, out, "Skipping Git checkout")
		assert.Contains(t, out, "pre-clone-script")
	})
}

func TestBuildWithGitSubmoduleStrategyRecursiveAndGitStrategyNone(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Variables = append(
			build.Variables,
			common.JobVariable{Key: "GIT_STRATEGY", Value: "none"},
			common.JobVariable{Key: "GIT_SUBMODULE_STRATEGY", Value: "recursive"},
		)

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.NotContains(t, out, "Created fresh repository")
		assert.NotContains(t, out, "Fetching changes")
		assert.Contains(t, out, "Skipping Git repository setup")
		assert.NotContains(t, out, "Updating/initializing submodules...")
		assert.NotContains(t, out, "Updating/initializing submodules recursively...")
		assert.Contains(t, out, "Skipping Git submodules setup")
	})
}

func TestBuildWithoutDebugTrace(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		// The default build shouldn't have debug tracing enabled
		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.NotRegexp(t, `[^$] echo Hello World`, out)
	})
}

func TestBuildWithDebugTrace(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Variables = append(build.Variables, common.JobVariable{Key: "CI_DEBUG_TRACE", Value: "true"})

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Regexp(t, `(>|[^$] )echo Hello World`, out)
	})
}

func TestBuildMultilineCommand(t *testing.T) {
	buildGenerators := map[string]func() (common.JobResponse, error){
		"bash":       common.GetMultilineBashBuild,
		"powershell": common.GetMultilineBashBuildPowerShell,
		"pwsh":       common.GetMultilineBashBuildPowerShell,
		"cmd":        common.GetMultilineBashBuildCmd,
	}

	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		buildGenerator, ok := buildGenerators[shell]
		require.Truef(t, ok, "Missing build generator for shell %q", shell)

		multilineBuild, err := buildGenerator()
		require.NoError(t, err)

		build, cleanup := newBuild(t, multilineBuild, shell)
		defer cleanup()

		// The default build shouldn't have debug tracing enabled
		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.NotContains(t, out, "echo")
		assert.Contains(t, out, "Hello World")
		assert.Contains(t, out, "collapsed multi-line command")
	})
}

func TestBuildWithGoodGitSSLCAInfo(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		if shell == "cmd" {
			t.Skip("This test doesn't support Windows CMD (which is deprecated)")
		}

		successfulBuild, err := common.GetRemoteGitLabComTLSBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Runner.URL = "https://gitlab.com"

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Created fresh repository")
		assert.Contains(t, out, "Updating/initializing submodules")
	})
}

// TestBuildWithGitSSLAndStrategyFetch describes issue https://gitlab.com/gitlab-org/gitlab-runner/issues/2991
func TestBuildWithGitSSLAndStrategyFetch(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetRemoteGitLabComTLSBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()

		build.Runner.PreCloneScript = "echo pre-clone-script"
		build.Variables = append(build.Variables, common.JobVariable{Key: "GIT_STRATEGY", Value: "fetch"})

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Created fresh repository")
		assert.Regexp(t, "Checking out [a-f0-9]+ as", out)

		out, err = buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Fetching changes")
		assert.Regexp(t, "Checking out [a-f0-9]+ as", out)
		assert.Contains(t, out, "pre-clone-script")
	})
}

func TestBuildChangesBranchesWhenFetchingRepo(t *testing.T) {
	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		successfulBuild, err := common.GetRemoteSuccessfulBuild()
		require.NoError(t, err)

		build, cleanup := newBuild(t, successfulBuild, shell)
		defer cleanup()
		build.Variables = append(build.Variables, common.JobVariable{Key: "GIT_STRATEGY", Value: "fetch"})

		out, err := buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Created fresh repository")

		// Another build using the same repo but different branch.
		build.GitInfo = common.GetLFSGitInfo(build.GitInfo.RepoURL)
		out, err = buildtest.RunBuildReturningOutput(t, build)
		assert.NoError(t, err)
		assert.Contains(t, out, "Checking out 2371dd05 as add-lfs-object...")
	})
}

func TestBuildPowerShellCatchesExceptions(t *testing.T) {
	for _, shell := range []string{"powershell", "pwsh"} {
		t.Run(shell, func(t *testing.T) {
			helpers.SkipIntegrationTests(t, shell)

			successfulBuild, err := common.GetRemoteSuccessfulBuild()
			require.NoError(t, err)

			build, cleanup := newBuild(t, successfulBuild, shell)
			defer cleanup()
			build.Variables = append(
				build.Variables,
				common.JobVariable{Key: "ErrorActionPreference", Value: "Stop"},
				common.JobVariable{Key: "GIT_STRATEGY", Value: "fetch"},
			)

			out, err := buildtest.RunBuildReturningOutput(t, build)
			assert.NoError(t, err)
			assert.Contains(t, out, "Created fresh repository")

			out, err = buildtest.RunBuildReturningOutput(t, build)
			assert.NoError(t, err)
			assert.NotContains(t, out, "Created fresh repository")
			assert.Regexp(t, "Checking out [a-f0-9]+ as", out)

			build.Variables = append(
				build.Variables,
				common.JobVariable{Key: "ErrorActionPreference", Value: "Continue"},
			)
			out, err = buildtest.RunBuildReturningOutput(t, build)
			assert.NoError(t, err)
			assert.NotContains(t, out, "Created fresh repository")
			assert.Regexp(t, "Checking out [a-f0-9]+ as", out)

			build.Variables = append(
				build.Variables,
				common.JobVariable{Key: "ErrorActionPreference", Value: "SilentlyContinue"},
			)
			out, err = buildtest.RunBuildReturningOutput(t, build)
			assert.NoError(t, err)
			assert.NotContains(t, out, "Created fresh repository")
			assert.Regexp(t, "Checking out [a-f0-9]+ as", out)
		})
	}
}

func TestBuildOnCustomDirectory(t *testing.T) {
	commands := map[string]string{
		"bash":       "pwd",
		"powershell": "pwd",
		"pwsh":       "pwd",
	}

	tests := map[string]bool{
		"custom directory defined":     true,
		"custom directory not defined": false,
	}

	shellstest.OnEachShell(t, func(t *testing.T, shell string) {
		if shell == "cmd" {
			t.Skip("This test doesn't support Windows CMD (which is deprecated)")
		}

		for testName, tt := range tests {
			t.Run(testName, func(t *testing.T) {
				cmd, ok := commands[shell]
				require.Truef(t, ok, "Missing command for shell %q", shell)

				dir := filepath.Join(os.TempDir(), "custom", "directory")
				expectedDirectory := filepath.Join(dir, "0")

				successfulBuild, err := common.GetSuccessfulBuild()
				require.NoError(t, err)

				successfulBuild.Steps[0].Script = common.StepScript{cmd}

				build, cleanup := newBuild(t, successfulBuild, shell)
				defer cleanup()

				if tt {
					build.Variables = append(build.Variables, common.JobVariable{
						Key:    "IS_RUN_ON_CUSTOM_DIR",
						Value:  dir,
						Public: true,
					})
				}

				out, err := buildtest.RunBuildReturningOutput(t, build)
				assert.NoError(t, err)

				if tt {
					assert.Contains(t, out, expectedDirectory)
				} else {
					assert.NotContains(t, out, expectedDirectory)
				}
			})
		}
	})
}
