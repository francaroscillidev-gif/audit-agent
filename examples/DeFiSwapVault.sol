// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

contract DeFiSwapVault {
    address public routerAddress = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    uint256 public constant FEE = 30;

    // MEV VULNERABILITY: amountOutMin set to 0 and deadline set to block.timestamp!
    function swapTokens(address tokenIn, address tokenOut, uint256 amountIn) external {
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;

        // Zero slippage protection -> MEV sandwich attack opportunity!
        IUniswapV2Router(routerAddress).swapExactTokensForTokens(
            amountIn,
            0,
            path,
            msg.sender,
            block.timestamp
        );
    }

    // GAS OPTIMIZATION: string memory in external function should be calldata
    function updateMetadata(string memory newName) external {
        // ...
    }

    // GAS OPTIMIZATION: loop counter can be unchecked
    function batchProcess(uint256[] calldata items) external pure returns (uint256 total) {
        for (uint256 i = 0; i < items.length; i++) {
            total += items[i];
        }
    }
}
