// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVault
 * @notice Example contract demonstrating business logic flaws and false positive testing.
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Legitimate deposit
    function deposit() external payable {
        require(msg.value > 0, "Deposit must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY 1: Reentrancy (Checks-Effects-Interactions violation)
    // External call made BEFORE balance is updated!
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // External call to recipient (invokes attacker receive/fallback hook)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens too late!
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);
    }

    // VULNERABILITY 2: Authorization Bypass (missing onlyOwner modifier)
    function setOwner(address newOwner) external {
        // Missing require(msg.sender == owner) or onlyOwner modifier!
        owner = newOwner;
    }

    // SAFE FUNCTION: External call with proper Checks-Effects-Interactions
    // Static regex may flag the .transfer or .call, but the verifier will PRUNE this as a FALSE POSITIVE.
    function safeWithdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // Effect happens FIRST
        balances[msg.sender] = 0;

        // Interaction happens SECOND
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }
}
