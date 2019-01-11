package chain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
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
	// Group public key generated by protocol execution, nil if the protocol failed.
	GroupPublicKey []byte
	// Disqualified members. Length of the slice and order of members are the same
	// as in the members group. Disqualified members are marked as true. It is
	// kept in this form as an optimization for an on-chain storage.
	Disqualified []bool
	// Inactive members. Length of the slice and order of members are the same
	// as in the members group. Disqualified members are marked as true. It is
	// kept in this form as an optimization for an on-chain storage.
	Inactive []bool
}

// Equals checks if two DKG results are equal.
func (r1 *DKGResult) Equals(r2 *DKGResult) bool {
	if r1 == nil || r2 == nil {
		return r1 == r2
	}
	if r1.Success != r2.Success {
		return false
	}
	if !bytes.Equal(r1.GroupPublicKey, r2.GroupPublicKey) {
		return false
	}
	if !boolSlicesEqual(r1.Disqualified, r2.Disqualified) {
		return false
	}
	if !boolSlicesEqual(r1.Inactive, r2.Inactive) {
		return false
	}
	return true
}

// bigIntEquals checks if two big.Int values are equal.
func bigIntEquals(expected *big.Int, actual *big.Int) bool {
	if expected != nil && actual != nil {
		return expected.Cmp(actual) == 0
	}
	return expected == nil && actual == nil
}

// boolSlicesEqual checks if two slices of bool are equal. Slices need to have
// the same length and have the same order of entries.
func boolSlicesEqual(expectedSlice []bool, actualSlice []bool) bool {
	if len(expectedSlice) != len(actualSlice) {
		return false
	}
	for i := range expectedSlice {
		if expectedSlice[i] != actualSlice[i] {
			return false
		}
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
	buf.Write(gpk)                                                         // Byte 5..X - the group public key in bytes
	err = binary.Write(&buf, binary.BigEndian, int32(len(r.Disqualified))) // Byte X+1..X+5 - length of the set of Disqualified
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid Type: [%v]\n", err)
	}
	for _, b := range r.Disqualified { // Byte X+6..Y - Set of disqualified as 0x01, 0x00 for true/false
		buf.Write(boolToByte(b))
	}
	err = binary.Write(&buf, binary.BigEndian, int32(len(r.Inactive))) // Byte Y+1..Y+5 - length of the set of Inactive
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid Type: [%v]\n", err)
	}
	for _, b := range r.Inactive { // Byte X+6..Y - Set of inactive as 0x01, 0x00 for true/false
		buf.Write(boolToByte(b))
	}
	return buf.Bytes()
}
