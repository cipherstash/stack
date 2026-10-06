// Package pb stands in for protoc-gen-go output: exported fields beside
// unexported ones, so the struct cannot convert to a copy of its fields.
package pb

type state struct{ _ [0]func() }

type Individual struct {
	state      state
	sizeCache  int32
	Id         int64  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Name       string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Email      string `protobuf:"bytes,3,opt,name=email,proto3" json:"email,omitempty"`
	MedicareNo string `protobuf:"bytes,4,opt,name=medicare_no,json=medicareNo,proto3" json:"medicare_no,omitempty"`
	Nickname   string `protobuf:"bytes,5,opt,name=nickname,proto3" json:"nickname,omitempty"`
}
