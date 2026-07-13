package cloudvm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockProvider implements Provider for testing without cloud credentials.
type MockProvider struct {
	mu     sync.Mutex
	id     ProviderID
	vms    map[string]*VMInfo
	nextID int

	// Configurable errors for testing failure paths
	CreateErr  error
	DestroyErr error
	GetErr     error
	CLIErr     error
	WaitErr    error

	// DestroyCtx records the context passed to the most recent DestroyVM, so
	// tests can assert cleanup uses a fresh (non-cancelled) context.
	DestroyCtx context.Context

	// LastCreateOpts records the options of the most recent CreateVM, so tests can
	// assert the provisioning shape (confidential type, enclave support, etc.).
	LastCreateOpts VMOptions

	// Lima-style overrides: when set, CreateVM populates these on the
	// returned VMInfo so tests can exercise the provider-supplied-identity
	// path (the same code path Lima uses).
	OverrideSSHKeyPath string
	OverrideSSHUser    string
	OverrideSSHPort    int
}

// NewMockProvider creates a new mock provider.
func NewMockProvider(id ProviderID) *MockProvider {
	return &MockProvider{
		id:  id,
		vms: make(map[string]*VMInfo),
	}
}

func (m *MockProvider) Name() ProviderID { return m.id }

func (m *MockProvider) CheckCLI(_ context.Context) error {
	return m.CLIErr
}

func (m *MockProvider) CreateVM(_ context.Context, opts VMOptions) (*VMInfo, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.LastCreateOpts = opts
	m.nextID++
	id := fmt.Sprintf("mock-%s-%d", m.id, m.nextID)
	vm := &VMInfo{
		ID:         id,
		Name:       opts.Name,
		IP:         fmt.Sprintf("10.0.0.%d", m.nextID),
		SSHPort:    m.OverrideSSHPort,
		SSHKeyPath: m.OverrideSSHKeyPath,
		SSHUser:    m.OverrideSSHUser,
		State:      VMStateRunning,
		CreatedAt:  time.Now().UTC(),
		Tags:       opts.Tags,
	}
	m.vms[id] = vm
	return vm, nil
}

func (m *MockProvider) WaitReady(_ context.Context, _ string, _ string, _ string) error {
	return m.WaitErr
}

func (m *MockProvider) GetVM(_ context.Context, vmID string) (*VMInfo, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	vm, ok := m.vms[vmID]
	if !ok {
		return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
	}
	return vm, nil
}

func (m *MockProvider) DestroyVM(ctx context.Context, vmID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DestroyCtx = ctx
	if m.DestroyErr != nil {
		return m.DestroyErr
	}
	if vm, ok := m.vms[vmID]; ok {
		vm.State = VMStateTerminated
		delete(m.vms, vmID)
	}
	return nil
}

func (m *MockProvider) ListVMs(_ context.Context, tags map[string]string) ([]VMInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []VMInfo
	for _, vm := range m.vms {
		match := true
		for k, v := range tags {
			if vm.Tags[k] != v {
				match = false
				break
			}
		}
		if match {
			result = append(result, *vm)
		}
	}
	return result, nil
}

// VMCount returns the number of active VMs (for test assertions).
func (m *MockProvider) VMCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.vms)
}
