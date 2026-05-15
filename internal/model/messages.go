package model

type DefaultKeyChangedMsg struct {
	Fingerprint string
}

type EditorResultMsg struct {
	Content string
	Err     error
}

type SignatureInfo struct {
	IsSigned          bool
	Valid             bool
	SignerFingerprint string
	SignerUserID      string
}
