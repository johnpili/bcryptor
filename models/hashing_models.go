package models

type HashModel struct {
	Plaintext string `json:"plaintext"`
}

type CheckModel struct {
	CheckHashedText string `json:"checkHashedText"`
	CheckPlaintext  string `json:"checkPlaintext"`
}
