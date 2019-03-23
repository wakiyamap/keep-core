pragma solidity ^0.5.4;

import "openzeppelin-solidity/contracts/token/ERC20/ERC20.sol";
import "openzeppelin-solidity/contracts/token/ERC20/SafeERC20.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/cryptography/ECDSA.sol";
import "solidity-bytes-utils/contracts/BytesLib.sol";
import "./StakingProxy.sol";
import "./utils/UintArrayUtils.sol";


/**
 * @title TokenStaking
 * @dev A token staking contract for a specified standard ERC20 token.
 * A holder of the specified token can stake its tokens to this contract
 * and unstake after withdrawal delay is over.
 */
contract TokenStaking {
    using SafeMath for uint256;
    using SafeERC20 for ERC20;
    using UintArrayUtils for uint256[];
    using BytesLib for bytes;
    using ECDSA for bytes32;

    ERC20 public token;
    StakingProxy public stakingProxy;

    event ReceivedApproval(uint256 _value);
    event Staked(address indexed from, uint256 value);
    event InitiatedUnstake(uint256 id);
    event FinishedUnstake(uint256 id);

    struct Withdrawal {
        address staker;
        uint256 amount;
        uint256 createdAt;
    }

    uint256 public withdrawalDelay;
    uint256 public numWithdrawals;

    mapping(address => uint256) public balances;
    mapping(address => uint256[]) public withdrawalIndices;
    mapping(uint256 => Withdrawal) public withdrawals;
    mapping(address => address) public operatorToOwner;
    mapping(address => address) public magpieToOwner;

    /**
     * @dev Creates a token staking contract for a provided Standard ERC20 token.
     * @param _tokenAddress Address of a token that will be linked to this contract.
     * @param _stakingProxy Address of a staking proxy that will be linked to this contract.
     * @param _delay Withdrawal delay for unstake.
     */
    constructor(address _tokenAddress, address _stakingProxy, uint256 _delay) public {
        require(_tokenAddress != address(0x0), "Token address can't be zero.");
        token = ERC20(_tokenAddress);
        stakingProxy = StakingProxy(_stakingProxy);
        withdrawalDelay = _delay;
    }

    /**
     * @notice Receives approval of token transfer and stakes the approved ammount.
     * @dev Makes sure provided token contract is the same one linked to this contract.
     * @param _from The owner of the tokens who approved them to transfer.
     * @param _value Approved amount for the transfer and stake.
     * @param _token Token contract address.
     * @param _extraData Data for stake delegation. This byte array must have the
     * following values concatenated: Magpie address (20 bytes) where the rewards for participation
     * are sent and the operator's ECDSA (65 bytes) signature of the address of the stake owner.
     */
    function receiveApproval(address _from, uint256 _value, address _token, bytes memory _extraData) public {
        emit ReceivedApproval(_value);

        require(ERC20(_token) == token, "Token contract must be the same one linked to this contract.");
        require(_value <= token.balanceOf(_from), "Sender must have enough tokens.");
        require(_extraData.length == 85, "Stake delegation data must be provided.");

        address magpie = _extraData.toAddress(0);
        address operator = keccak256(abi.encodePacked(_from)).toEthSignedMessageHash().recover(_extraData.slice(20, 65));
        require(operatorToOwner[operator] == address(0), "Operator address is already in use.");

        operatorToOwner[operator] = _from;
        magpieToOwner[magpie] = _from;

        // Transfer tokens to this contract.
        token.transferFrom(_from, address(this), _value);

        // Maintain a record of the stake amount by the sender.
        balances[operator] = balances[operator].add(_value);
        emit Staked(operator, _value);
        if (address(stakingProxy) != address(0)) {
            stakingProxy.emitStakedEvent(operator, _value);
        }
    }

    /**
     * @notice Initiates unstake of staked tokens and returns withdrawal request ID.
     * You will be able to call `finishUnstake()` with this ID and finish
     * unstake once withdrawal delay is over.
     * @param _value The amount to be unstaked.
     */
    function initiateUnstake(uint256 _value, address _operator) public returns (uint256 id) {

        require(msg.sender == operatorToOwner[_operator], "Only owner of the stake can initiate unstake.");
        require(_value <= balances[_operator], "Staker must have enough tokens to unstake.");

        balances[_operator] = balances[_operator].sub(_value);

        id = numWithdrawals++;
        withdrawals[id] = Withdrawal(msg.sender, _value, now);
        withdrawalIndices[msg.sender].push(id);
        emit InitiatedUnstake(id);
        if (address(stakingProxy) != address(0)) {
            stakingProxy.emitUnstakedEvent(msg.sender, _value);
        }
        return id;
    }

    /**
     * @notice Finishes unstake of the tokens of provided withdrawal request.
     * You can only finish unstake once withdrawal delay is over for the request,
     * otherwise the function will fail and remaining gas is returned.
     * @param _id Withdrawal ID.
     */
    function finishUnstake(uint256 _id) public {
        require(now >= withdrawals[_id].createdAt.add(withdrawalDelay), "Can not finish unstake before withdrawal delay is over.");

        address staker = withdrawals[_id].staker;

        // No need to call approve since msg.sender will be this staking contract.
        token.safeTransfer(staker, withdrawals[_id].amount);

        // Cleanup withdrawal index.
        withdrawalIndices[staker].removeValue(_id);

        // Cleanup withdrawal record.
        delete withdrawals[_id];

        emit FinishedUnstake(_id);
    }

    /**
     * @dev Gets the stake balance of the specified address.
     * @param _staker The address to query the balance of.
     * @return An uint256 representing the amount owned by the passed address.
     */
    function stakeBalanceOf(address _staker) public view returns (uint256 balance) {
        return balances[_staker];
    }

    /**
     * @dev Gets withdrawal request by ID.
     * @param _id ID of withdrawal request.
     * @return staker, amount, createdAt.
     */
    function getWithdrawal(uint256 _id) public view returns (address, uint256, uint256) {
        return (withdrawals[_id].staker, withdrawals[_id].amount, withdrawals[_id].createdAt);
    }

    /**
     * @dev Gets withdrawal ids of the specified address.
     * @param _staker The address to query.
     * @return An uint256 array of withdrawal IDs.
     */
    function getWithdrawals(address _staker) public view returns (uint256[] memory) {
        return withdrawalIndices[_staker];
    }

    // TODO: replace with a secure authorization protocol (addressed in RFC 4).
    function authorizedTransferFrom(address from, address to, uint256 amount) public {
        balances[from] = balances[from].sub(amount);
        balances[to] = balances[to].add(amount);
    }

}
