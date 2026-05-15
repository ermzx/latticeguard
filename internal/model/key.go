package model

import "time"

type KeyInfo struct {
	Fingerprint string
	UserID      string
	Algorithm   string
	SubkeyAlgo  string
	Created     time.Time
	Expires     *time.Time
	HasPrivate  bool
	IsDefault   bool
}

type KeyList struct {
	MyKeys       []KeyInfo
	ImportedKeys []KeyInfo
}
