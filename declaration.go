package main

type GetDeclarationResp struct {
	Cid   *string     `json:"cid,omitempty"`
	Uri   string      `json:"uri"`
	Value Declaration `json:"value"`
}

type PutDeclarationBody struct {
	Repo       string      `json:"repo"`
	Collection string      `json:"collection"`
	Rkey       string      `json:"rkey,omitempty"`
	SwapCommit *string     `json:"swapCommit,omitempty"`
	Validate   *bool       `json:"validate,omitempty"`
	Record     Declaration `json:"record"`
}

type DeclarationIntent struct {
	Allow *bool  `json:"allow,omitempty"`
	UpdatedAt string `json:"updatedAt"`
}

type Declaration struct {
	Type                       string             `json:"$type"`
	UpdatedAt                  string             `json:"updatedAt,omitempty"`
	SyntheticContentGeneration *DeclarationIntent `json:"syntheticContentGeneration,omitempty"`
	PublicAccessArchive        *DeclarationIntent `json:"publicAccessArchive,omitempty"`
	BulkDataset *DeclarationIntent `json:"bulkDataset,omitempty"`
	ProtocolBridging           *DeclarationIntent `json:"protocolBridging,omitempty"`
}
