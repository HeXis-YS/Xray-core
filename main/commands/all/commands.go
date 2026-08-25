package all

import (
	"github.com/xtls/xray-core/main/commands/base"
)

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		cmdUUID,
		cmdX25519,
		cmdWG,
		cmdMLDSA65,
		cmdMLKEM768,
		cmdVLESSEnc,
	)
}
