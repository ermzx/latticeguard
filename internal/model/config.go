package model

type Config struct {
	DataDir     string `json:"data_dir"`
	Editor      string `json:"editor"`
	DefaultAlgo int    `json:"default_algo"`
	DefaultKey  string `json:"default_key"`
}

func DefaultConfig() Config {
	return Config{
		DataDir:     "./data",
		Editor:      "nano",
		DefaultAlgo: 30, // packet.PubKeyAlgoMldsa65Ed25519
	}
}
