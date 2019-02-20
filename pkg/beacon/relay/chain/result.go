package chain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto/sha3"
)

// DKGResult is a result of distributed key generation protocol.
//
// Success means that the protocol execution finished with acceptable number of
// disqualified or inactive members. The group of remaining members should be
// added to the signing groups for the threshold relay.
//
// Failure means that the group creation could not finish, due to either the number
// of inactive or disqualified participants, or the presented results being
// disputed in a way where the correct outcome cannot be ascertained.
type DKGResult struct {
	// Result type of the protocol execution. True if success, false if failure.
	Success bool
	// Group public key generated by protocol execution, empty if the protocol failed.
	GroupPublicKey []byte
	// Disqualified members are represented as a slice of bytes for optimizing
	// on-chain storage. The length of the slice, and ordering of the members is
	// the same as the members group. Disqualified members are marked as 0x01,
	// non-disqualified members as 0x00.
	Disqualified []byte
	// Inactive members are represented as a slice of bytes for optimizing
	// on-chain storage. The length of the slice, and ordering of the members is
	// the same as the members group. Inactive members are marked as 0x01,
	// active members as 0x00.
	Inactive []byte
}

// Equals checks if two DKG results are equal.
func (r *DKGResult) Equals(r2 *DKGResult) bool {
	if r == nil || r2 == nil {
		return r == r2
	}
	if r.Success != r2.Success {
		return false
	}
	if !bytes.Equal(r.GroupPublicKey, r2.GroupPublicKey) {
		return false
	}
	if !bytes.Equal(r.Disqualified, r2.Disqualified) {
		return false
	}
	if !bytes.Equal(r.Inactive, r2.Inactive) {
		return false
	}
	return true
}

// Hash the DKGResult and return the hashed value.
func (r *DKGResult) Hash() []byte {
	serial := r.serialize()
	d := sha3.NewKeccak256()
	d.Write(serial)
	return d.Sum(nil)
}

// serialize converts the DKGResult into bytes.  This is so that it can be hashed.
// Format:
// Byte 0 - 0x01 == true, 0x00 == false - r1.Success
// Byte 1..4 - length of the group public key in BigEndian format
// Byte 5..X - the group public key in bytes
// Byte X+1..X+5 - length of the set of Disqualified
// Byte X+6..Y - Set of disqualified as 0x01, 0x00 for true/false
// Byte Y+1..Y+5 - length of the set of Inactive
// Byte X+6..Y - Set of inactive as 0x01, 0x00 for true/false
func (r *DKGResult) serialize() []byte {
	boolToByte := func(b bool) []byte {
		if b {
			return []byte{0x01}
		}
		return []byte{0x00}
	}

	var buf bytes.Buffer
	buf.Write(boolToByte(r.Success)) // Byte 0 - 0x01 == true, 0x00 == false - r1.Success

	gpk := r.GroupPublicKey
	err := binary.Write(&buf, binary.BigEndian, int32(len(gpk))) // Byte 1..4 - length of the group public key in BigEndian format
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid Type: [%v]\n", err)
	}
	buf.Write(gpk) // Byte 5..X - the group public key in bytes

	err = binary.Write(&buf, binary.BigEndian, int32(len(r.Disqualified))) // Byte X+1..X+5 - length of the set of Disqualified
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid Type: [%v]\n", err)
	}
	buf.Write(r.Disqualified)                                          // Byte X+6..Y - Set of disqualified as 0x01, 0x00 for true/false
	err = binary.Write(&buf, binary.BigEndian, int32(len(r.Inactive))) // Byte Y+1..Y+5 - length of the set of Inactive
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid Type: [%v]\n", err)
	}
	buf.Write(r.Inactive) // Byte X+6..Y - Set of inactive as 0x01, 0x00 for true/false

	return buf.Bytes()
}
