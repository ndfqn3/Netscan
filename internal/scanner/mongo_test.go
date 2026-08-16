package scanner

import (
	"encoding/binary"
	"testing"
)

func TestMongoIsMasterLen(t *testing.T) {
	msg := mongoIsMaster()
	declared := int(binary.LittleEndian.Uint32(msg[0:4]))
	if declared != len(msg) {
		t.Fatalf("messageLength 字段 %d != 实际 %d", declared, len(msg))
	}
	// OP_QUERY 布局: 16 头 + 4 flags + "admin.$cmd\0" + 4 skip + 4 return + bson
	bsonOff := 16 + 4 + len("admin.$cmd") + 1 + 4 + 4
	bsonLen := int(binary.LittleEndian.Uint32(msg[bsonOff : bsonOff+4]))
	if bsonLen != len(msg)-bsonOff {
		t.Fatalf("BSON 文档长度字段 %d != 实际 %d", bsonLen, len(msg)-bsonOff)
	}
}
