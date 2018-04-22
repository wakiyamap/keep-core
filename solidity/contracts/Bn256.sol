pragma solidity ^0.4.22;
library Bn256 {

    function scalarMultiply(uint256[2] p_1, uint256 scalar) public view returns (uint256[2] p_2) {
        // Scalar multiplication of a point on bn256
        uint256[3] memory arg;
        arg[0] = p_1[0];
        arg[1] = p_1[1];
        arg[2] = scalar;
        assembly {
            if iszero(call(not(0), 0x07, 0, arg, 0x60, p_2, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function add(uint256[2] a, uint256[2] b) public view returns (uint256[2] c) {
        uint256[4] memory arg;
        arg[0] = a[0];
        arg[1] = a[1];
        arg[2] = b[0];
        arg[3] = b[1];
        assembly {
            if iszero(call(not(0), 0x06, 0, arg, 0x80, c, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function hashToG1() public view returns (G1Point g2) {
    }
}
