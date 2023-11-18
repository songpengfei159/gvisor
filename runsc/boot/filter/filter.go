// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package filter installs seccomp filters to prevent prohibited syscalls
// in case it's compromised.
package filter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/boot/filter/config"
)

// Options is a re-export of the config Options type under this package.
type Options = config.Options

// Install seccomp filters based on the given platform.
func Install(opt Options) error {
	for _, warning := range config.Warnings(opt) {
		log.Warningf("*** SECCOMP WARNING: %s", warning)
	}
	precompiled, found := GetPrecompiled(opt.ConfigKey())
	if found {
		log.Debugf("Loaded precompiled seccomp instructions for options %v, using variables: %v", opt.ConfigKey(), opt.Vars())
		insns, err := precompiled.RenderInstructions(opt.Vars())
		if err != nil {
			return fmt.Errorf("cannot render precompiled program for options %v: %w", opt, err)
		}
		return seccomp.SetFilter(insns)
	}
	log.Infof("No precompiled program found for config options %v, building seccomp program from scratch. This may slow down container startup.", opt)
	rules, denyRules := config.Rules(opt)
	return seccomp.Install(rules, denyRules, config.SeccompOptions(opt))
}
