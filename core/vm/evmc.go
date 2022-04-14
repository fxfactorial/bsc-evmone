// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/evmc/v10/bindings/go/evmc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type EVMC struct {
	instance *evmc.VM
	env      *EVM
	readOnly bool // TODO: The readOnly flag should not be here.
}

var (
	createMu     sync.Mutex
	evmcConfig   string // The configuration the instance was created with.
	evmcInstance *evmc.VM
	once         sync.Once
)

func createVM(config string) (*evmc.VM, error) {

	if evmcInstance == nil {
		once.Do(func() {

			options := strings.Split(config, ",")
			path := options[0]

			if path == "" {
				panic("EVMC VM path not provided, set --vm.(evm|ewasm)=/path/to/vm")
			}

			var err error
			evmcInstance, err = evmc.Load(path)
			if err != nil {
				panic(err)
			}

			fmt.Println("EVMC VM loaded", "name", evmcInstance.Name(), "version", evmcInstance.Version(), "path", path)

			for _, option := range options[1:] {
				if idx := strings.Index(option, "="); idx >= 0 {
					name := option[:idx]
					value := option[idx+1:]
					err := evmcInstance.SetOption(name, value)
					if err == nil {
						fmt.Println("EVMC VM option set", "name", name, "value", value)
					} else {
						fmt.Println("EVMC VM option setting failed", "name", name, "error", err)
					}
				}
			}

			evm1Cap := evmcInstance.HasCapability(evmc.CapabilityEVM1)
			ewasmCap := evmcInstance.HasCapability(evmc.CapabilityEWASM)
			fmt.Println("EVMC VM capabilities", "evm1", evm1Cap, "ewasm", ewasmCap)
			evmcConfig = config // Remember the config.
		})
	} else if evmcConfig != config {
		fmt.Println("New EVMC VM requested", "newconfig", config, "oldconfig", evmcConfig)
	}

	return evmcInstance, nil
}

func NewEVMC(options string, env *EVM) (*EVMC, error) {
	handle, err := createVM(options)
	if err != nil {
		return nil, err
	}
	return &EVMC{handle, env, false}, nil
}

// Implements evmc.HostContext interface.
type HostContext struct {
	env      *EVM
	contract *Contract
}

func (host *HostContext) AccountExists(addr evmc.Address) bool {
	env := host.env
	eip158 := env.ChainConfig().IsEIP158(env.Context.BlockNumber)
	if eip158 {
		if !env.StateDB.Empty(common.Address(addr)) {
			return true
		}
	} else if env.StateDB.Exist(common.Address(addr)) {
		return true
	}
	return false
}

func (host *HostContext) GetStorage(addr evmc.Address, key evmc.Hash) evmc.Hash {
	env := host.env
	return evmc.Hash(env.StateDB.GetState(common.Address(addr), common.Hash(key)))
}

func (host *HostContext) SetStorage(
	addr evmc.Address, key evmc.Hash, value evmc.Hash,
) (status evmc.StorageStatus) {
	env := host.env

	oldValue := env.StateDB.GetState(common.Address(addr), common.Hash(key))
	if evmc.Hash(oldValue) == value {
		return evmc.StorageUnchanged
	}

	current := env.StateDB.GetState(common.Address(addr), common.Hash(key))
	original := env.StateDB.GetCommittedState(common.Address(addr), common.Hash(key))

	env.StateDB.SetState(common.Address(addr), common.Hash(key), common.Hash(value))

	hasNetStorageCostEIP := env.ChainConfig().IsConstantinople(env.Context.BlockNumber) &&
		!env.ChainConfig().IsPetersburg(env.Context.BlockNumber)
	if !hasNetStorageCostEIP {

		zero := common.Hash{}
		status = evmc.StorageModified
		if oldValue == zero {
			return evmc.StorageAdded
		} else if common.Hash(value) == zero {
			env.StateDB.AddRefund(params.SstoreRefundGas)
			return evmc.StorageDeleted
		}
		return evmc.StorageModified
	}

	if original == current {
		if original == (common.Hash{}) { // create slot (2.1.1)
			return evmc.StorageAdded
		}
		if common.Hash(value) == (common.Hash{}) { // delete slot (2.1.2b)
			env.StateDB.AddRefund(params.NetSstoreClearRefund)
			return evmc.StorageDeleted
		}
		return evmc.StorageModified
	}
	if original != (common.Hash{}) {
		if current == (common.Hash{}) { // recreate slot (2.2.1.1)
			env.StateDB.SubRefund(params.NetSstoreClearRefund)
		} else if common.Hash(value) == (common.Hash{}) { // delete slot (2.2.1.2)
			env.StateDB.AddRefund(params.NetSstoreClearRefund)
		}
	}
	if original == common.Hash(value) {
		if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
			env.StateDB.AddRefund(params.NetSstoreResetClearRefund)
		} else { // reset to original existing slot (2.2.2.2)
			env.StateDB.AddRefund(params.NetSstoreResetRefund)
		}
	}
	return evmc.StorageModifiedAgain
}

func (host *HostContext) GetBalance(addr evmc.Address) evmc.Hash {
	env := host.env
	balance := env.StateDB.GetBalance(common.Address(addr))
	return evmc.Hash(common.BigToHash(balance))
}

func (host *HostContext) GetCodeSize(addr evmc.Address) int {
	env := host.env
	return env.StateDB.GetCodeSize(common.Address(addr))
}

func (host *HostContext) GetCodeHash(addr evmc.Address) evmc.Hash {
	env := host.env
	if env.StateDB.Empty(common.Address(addr)) {
		return evmc.Hash{}
	}
	return evmc.Hash(env.StateDB.GetCodeHash(common.Address(addr)))
}

func (host *HostContext) GetCode(addr evmc.Address) []byte {
	env := host.env
	return env.StateDB.GetCode(common.Address(addr))
}

func (host *HostContext) Selfdestruct(addr evmc.Address, beneficiary evmc.Address) {
	env := host.env
	db := env.StateDB
	if !db.HasSuicided(common.Address(addr)) {
		db.AddRefund(params.SelfdestructRefundGas)
	}
	balance := db.GetBalance(common.Address(addr))
	db.AddBalance(common.Address(beneficiary), balance)
	db.Suicide(common.Address(addr))
}

var (
	fiveSix = evmc.Hash(common.BigToHash(big.NewInt(56)))
)

func (host *HostContext) GetTxContext() evmc.TxContext {
	env := host.env
	return evmc.TxContext{
		GasPrice:   evmc.Hash(common.BigToHash(env.GasPrice)),
		Origin:     evmc.Address(env.Origin),
		Coinbase:   evmc.Address(env.Context.Coinbase),
		Number:     env.Context.BlockNumber.Int64(),
		Timestamp:  env.Context.Time.Int64(),
		GasLimit:   int64(env.Context.GasLimit),
		Difficulty: evmc.Hash(common.BigToHash(env.Context.Difficulty)),
		ChainID:    fiveSix,
	}
}

func (host *HostContext) GetBlockHash(number int64) evmc.Hash {
	env := host.env
	b := env.Context.BlockNumber.Int64()
	if number >= (b-256) && number < b {
		return evmc.Hash(env.Context.GetHash(uint64(number)))
	}
	return evmc.Hash{}
}

func (host *HostContext) AccessAccount(addr evmc.Address) evmc.AccessStatus {
	return evmc.ColdAccess
}

func (host *HostContext) AccessStorage(addr evmc.Address, key evmc.Hash) evmc.AccessStatus {
	return evmc.ColdAccess
}

func (host *HostContext) EmitLog(addr evmc.Address, topics []evmc.Hash, data []byte) {
	env := host.env
	env.StateDB.AddLog(&types.Log{
		Address: common.Address(addr),
		// TODO use some reflection, unsafepointer to force cast it
		// Topics:      topics.([]common.Hash),
		Data:        data,
		BlockNumber: env.Context.BlockNumber.Uint64(),
	})
}

func (host *HostContext) Call(
	kind evmc.CallKind,
	destination evmc.Address,
	sender evmc.Address,
	value evmc.Hash,
	input []byte,
	gas int64,
	depth int,
	static bool,
	salt evmc.Hash,
	codeAddress evmc.Address,
) (output []byte, gasLeft int64, createAddr evmc.Address, err error) {

	env := host.env

	gasU := uint64(gas)
	var gasLeftU uint64

	switch kind {
	case evmc.Call:
		if static {
			output, gasLeftU, err = env.StaticCall(host.contract, common.Address(destination), input, gasU)
		} else {
			output, gasLeftU, err = env.Call(
				host.contract, common.Address(destination), input, gasU, new(big.Int).SetBytes(value[:]),
			)
		}
	case evmc.DelegateCall:
		output, gasLeftU, err = env.DelegateCall(host.contract, common.Address(destination), input, gasU)
	case evmc.CallCode:
		output, gasLeftU, err = env.CallCode(
			host.contract, common.Address(destination), input, gasU, new(big.Int).SetBytes(value[:]),
		)
	case evmc.Create:
		var createOutput []byte
		var createWrap common.Address
		createOutput, createWrap, gasLeftU, err = env.Create(host.contract, input, gasU, new(big.Int).SetBytes(value[:]))
		createAddr = evmc.Address(createWrap)
		isHomestead := env.ChainConfig().IsHomestead(env.Context.BlockNumber)
		if !isHomestead && err == ErrCodeStoreOutOfGas {
			err = nil
		}
		if err == ErrExecutionReverted {
			// Assign return buffer from REVERT.
			// TODO: Bad API design: return data buffer and the code is returned in the same place. In worst case
			//       the code is returned also when there is not enough funds to deploy the code.
			output = createOutput
		}
	case evmc.Create2:
		var createOutput []byte
		var createWrap common.Address
		saltWrapped, _ := uint256.FromBig(new(big.Int).SetBytes(salt[:]))
		createOutput, createWrap, gasLeftU, err = env.Create2(
			host.contract, input, gasU, new(big.Int).SetBytes(value[:]), saltWrapped,
		)
		createAddr = evmc.Address(createWrap)

		if err == ErrExecutionReverted {
			// Assign return buffer from REVERT.
			// TODO: Bad API design: return data buffer and the code is returned in the same place. In worst case
			//       the code is returned also when there is not enough funds to deploy the code.
			output = createOutput
		}
	default:
		panic(fmt.Errorf("EVMC: Unknown call kind %d", kind))
	}

	// Map errors.
	if err == ErrExecutionReverted {
		err = evmc.Revert
	} else if err != nil {
		err = evmc.Failure
	}

	gasLeft = int64(gasLeftU)
	return output, gasLeft, createAddr, err
}

func getRevision(env *EVM) evmc.Revision {
	return evmc.Berlin

	n := env.Context.BlockNumber
	conf := env.ChainConfig()

	if conf.IsBerlin(n) {
		return evmc.Berlin
	}
	if conf.IsIstanbul(n) {
		return evmc.Istanbul
	}
	if conf.IsPetersburg(n) {
		return evmc.Petersburg
	}
	if conf.IsConstantinople(n) {
		return evmc.Constantinople
	}
	if conf.IsByzantium(n) {
		return evmc.Byzantium
	}
	if conf.IsEIP158(n) {
		return evmc.SpuriousDragon
	}
	if conf.IsEIP150(n) {
		return evmc.TangerineWhistle
	}
	if conf.IsHomestead(n) {
		return evmc.Homestead
	}
	return evmc.Frontier
}

func (evm *EVMC) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	evm.env.depth++
	defer func() { evm.env.depth-- }()

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	kind := evmc.Call
	if evm.env.StateDB.GetCodeSize(contract.Address()) == 0 {
		// Guess if this is a CREATE.
		kind = evmc.Create
	}

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This makes also sure that the readOnly flag isn't removed for child calls.
	if readOnly && !evm.readOnly {
		evm.readOnly = true
		defer func() { evm.readOnly = false }()
	}

	cast1, cast2 :=
		evmc.Address(contract.Address()),
		evmc.Address(contract.Caller())
	rev := getRevision(evm.env)

	output, gasLeft, err := evm.instance.Execute(
		&HostContext{evm.env, contract},
		rev,
		kind,
		evm.readOnly,
		evm.env.depth-1,
		int64(contract.Gas),
		cast1, cast2,
		input,
		evmc.Hash(common.BigToHash(contract.value)),
		contract.Code,
	)

	contract.Gas = uint64(gasLeft)

	if err == evmc.Revert {
		err = ErrExecutionReverted
	} else if evmcError, ok := err.(evmc.Error); ok && evmcError.IsInternalError() {
		panic(fmt.Sprintf("EVMC VM internal error: %s", evmcError.Error()))
	}

	return output, err
}

func (evm *EVMC) CanRun(code []byte) bool {
	cap := evmc.CapabilityEVM1
	wasmPreamble := []byte("\x00asm")
	if bytes.HasPrefix(code, wasmPreamble) {
		cap = evmc.CapabilityEWASM
	}
	// FIXME: Optimize. Access capabilities once.
	return evm.instance.HasCapability(cap)
}
