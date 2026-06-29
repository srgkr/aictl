package ai

import (
	"context"
	"fmt"

	ai5x "github.com/POSIdev-community/aictl/internal/adapter/ai/5_x"
	ai6x "github.com/POSIdev-community/aictl/internal/adapter/ai/6_x"
	"github.com/POSIdev-community/aictl/internal/core/domain/version"
	"github.com/POSIdev-community/aictl/pkg/logger"
)

type initState struct {
	version      version.Version
	versionKnown bool
}

type clientInitAttempt func(ctx context.Context, state initState) (active ClientAi, nextState initState, matched bool, err error)

func (a *Adapter) Initialize(ctx context.Context) error {
	attempts := []clientInitAttempt{
		a.tryInitializeClient6x,
		a.tryInitializeClient5x,
	}

	state := initState{}

	for _, attempt := range attempts {
		activeClient, nextState, matched, err := attempt(ctx, state)
		state = nextState
		if err != nil {
			return err
		}
		if !matched {
			a.baseClient.Reset()
			continue
		}

		a.serverVersion = state.version
		a.activeClient = activeClient

		return a.activeClient.CheckLicense(ctx)
	}

	return fmt.Errorf("initialize ai client: no compatible client found")
}

func (a *Adapter) tryInitializeClient6x(ctx context.Context, state initState) (ClientAi, initState, bool, error) {
	client6x := ai6x.NewAiClient(a.baseClient)
	if err := client6x.Initialize(ctx, a.cfg); err != nil {
		return nil, state, false, nil
	}

	state, err := a.ensureVersion(ctx, state, client6x.GetVersion)
	if err != nil {
		return nil, state, false, nil
	}

	if !isClient6xVersion(state.version) {
		return nil, state, false, nil
	}

	if err := validateVersion(state.version); err != nil {
		return nil, state, false, fmt.Errorf("unsupported server version: %w", err)
	}

	return client6x, state, true, nil
}

func (a *Adapter) tryInitializeClient5x(ctx context.Context, state initState) (ClientAi, initState, bool, error) {
	client5x := ai5x.NewAiClient(a.baseClient)
	if err := client5x.Initialize(ctx, a.cfg); err != nil {
		return nil, state, false, fmt.Errorf("initialize ai client (5.x): %w", err)
	}

	state, err := a.ensureVersion(ctx, state, client5x.GetVersion)
	if err != nil {
		return nil, state, false, fmt.Errorf("get server version (5.x): %w", err)
	}

	if err := validateVersion(state.version); err != nil {
		return nil, state, false, fmt.Errorf("unsupported server version: %w", err)
	}

	return client5x, state, true, nil
}

func logInitSkip(ctx context.Context, format string, args ...any) {
	logger.FromContext(ctx).Debugf("ai client init: "+format+", trying 5.x client", args...)
}

func (a *Adapter) ensureVersion(
	ctx context.Context,
	state initState,
	getVersion func(context.Context) (version.Version, error),
) (initState, error) {
	if state.versionKnown {
		return state, nil
	}

	ver, err := getVersion(ctx)
	if err != nil {
		return state, err
	}

	return initState{version: ver, versionKnown: true}, nil
}

func isClient6xVersion(ver version.Version) bool {
	return !ver.Less(client6xMinVersion) && ver.Less(maxSupportedVersion)
}

func validateVersion(ver version.Version) error {
	if ver.Less(minSupportedVersion) {
		return fmt.Errorf("version less than 5.0.0")
	}

	if !ver.Less(maxSupportedVersion) {
		return fmt.Errorf("version greater or equal to 7.0.0")
	}

	return nil
}
