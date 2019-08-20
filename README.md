# Security considerations for EIP-1884


## Background

[EIP 1884](https://eips.ethereum.org/EIPS/eip-1884) is set to be implemented into the upcoming Ethereum 'Istanbul' hard fork. It 

- increases the cost of opcode `SLOAD` from `200` to `800` gas
- increases the cost of `BALANCE` and `EXTCODEHASH` from `400` to `700` gas
- adds a new opcode `SELFBALANCE` with cost `5`. 

The reasoning is that due to the increase in state size, and thus the added IO overhead for fetching tries from disk, the opcodes `SLOAD`, `BALANCE` and `EXTCODEHASH` have become disproportionally 'cheap', for the amount of work that a node has to perform. Having badly 'tuned' gas cost versus the underlying computational cost of an operation is a problem which can cause various problems, and pave the way for attacks such as the so called 'Shanghai attacks' as seen in late 2017. 

## Potential problems

In general, repricing opcodes can always break contracts that explicitly rely on assumptions of gas cost being constant. However, this has been considered bad practice for a long time, especially so since certain opcodes historically already _have_ been repriced in [Tangerine Whistle](https://eips.ethereum.org/EIPS/eip-150), where `SLOAD` was repriced from `50` to `200`. 

However, there is one case which could potentially become more problematic; `default` functions. 

### Default functions

A `default` function is a method of a contract that handles calls without any data -- they are there to handle transfers of ether that does not explicitly invoke any method at all. They are typically used to create an event using a `LOG` operation, so external systems can detect the event, and e.g. register that a transfer was made. 

A regular transfer of ether to a contract always gives the receiver at minimum `2300` as gas `stipend`. This number is meant to allow the recipient to issue an event, but is not sufficient to perform state changes (such as making another transfer, or updating a storage slot). 


### EIP 1884 and default functions

One potential problem of EIP-1884 is that `default` functions might start to fail on `2300` gas, e.g. for the following reasons:

* Limited wallets: A contract only allows payments if `balance(self)` is below a certain limit 
* Designated senders: A contract only allows payments from a set of pre-approved senders
* Disable:able wallets: A contract only allows payments if a certain variable (slot) is set to `true`. 

Now, if a `default` function cease to work with `2300` gas, this is not always a very serious problem. For example, if the caller is a so called `EOA` (Externally Owner Account - meaning end user), the caller can simply make sure to send a bit more than `21000` gas in the transaction. But the problem can arise if, for example

- The `target` has designated sender, 
- The `senders` are smart contracts, which are programmed to only ever use `transfer` with no extra gas. 

In that case, the flow of ether from the `senders` to the `target` would be broken in a way that is not 'fixable' unless other mechanisms can be used to handle the situation (e.g. replacing the senders). 

## Investigation

I reached out to the EthSecurity community to help assess this situation. Some notes:

- Contracts that does not have a `payable` default function would not be affected, 
- Contracts whose default function would not be executable today on `2300` gas would not be affected e.g. contracts that do SLOAD or transfer ether in `default` would already be 'broken'


Neville Grech, of [Contract Library](https://contract-library.com), performed a static analysis of partially decompiled mainnet contracts. The analysis covers about 95% of all contracts on mainnet, and from the last 500k blocks of testnets,  (400K unique bytecodes), and lists those that could potentially be affected.
  - The list is available [here](https://contract-library.com/?w=FALLBACK_WILL_FAIL) and is updated automatically
  
Note that static program analysis is a technique that considers all program's behaviors without having to execute the program. The static analysis is encoded in the following *simplified* datalog spec, deployed on contract-library.com:

```prolog
% Restrict the edges that form the possible paths to those in fallback functions
FallbackFunctionBlockEdge(from, to) :-
   GlobalBlockEdge(from, to), 
   InFunction(from, f), FallbackFunction(f),
   InFunction(to, g), FallbackFunction(g).

% Analyze the fallback function paths with the
% conventional gas semantics, taking shortest paths
GasCostAnalysis = new CostAnalysis(
  Block_Gas, FallbackFunctionBlockEdge, 2300, min
).

% Analyze the fallback function paths with the
% updated gas semantics, taking shortest paths
EIP1884GasCostAnalysis = new CostAnalysis(
  EIP1884Block_Gas, FallbackFunctionBlockEdge, 2300, min
).

FallbackWillFailAnyway(n - 2300) :-
   GasCostAnalysis(*, n), n > 2300.

% fallback will fail with n - m additional gas
EIP1884FallbackWillFail(n - m) :-
   EIP1884GasCostAnalysis(block, n), n > 2300,
   GasCostAnalysis(block, m),
   !FallbackWillFailAnyway(*).
``` 


The analysis performs a gas cost computation over all possible paths in the fallback functions, using the gas cost semantics of both PRE and POST EIP-1884. In cases where there is a path that can complete in the former semantics but not the latter, we flag the smart contract.

The analysis automatically flagged over 200 smart contracts on the mainnet, including the [Kyber Network](https://contract-library.com/contracts/Ethereum/0x91b9d2835ad914bc1dcfe09bd1816febd04fd689) contract and the [CappedVault](https://contract-library.com/contracts/Ethereum/0x91b9d2835ad914bc1dcfe09bd1816febd04fd689) contract mentioned below. Note that the CappedVault contract will still keep working if the BALANCE opcode's gas requirements are lowered, say to 600. It however also finds several potential other contracts (with balance) that can fail the fallback under various circumstances with the new gas semantics:

[This one](https://contract-library.com/contracts/Ethereum/0x690858a9ab0d9afa707f1438fc175cca6be1a1db) contains more than 580 ETH and will stop accepting unsolicited donations :)
Same for the [NEXXO crowdsale](https://contract-library.com/contracts/Ethereum/0x2c7fa71e31c0c6bb9f21fc3c098ac2c53f8598cc) and for the [Crowd Machine Compute Token crowdsale](https://contract-library.com/contracts/Ethereum/0x5fe56cb82b3d88b6e37d3a9dba8f5b40b28dda7e).



Hubert Ritzdorf, of [ChainSecurity](https://chainsecurity.com/), performed an analysis of recent transactions. The analysis is based on investigating actual transactions on mainnet, and seeing which of those would have failed if `SLOAD` had cost `800` instead of `200`. Partial results are [here](https://gist.github.com/ritzdorf/1c6bd72955391e831f8a397d3152b4e0). 

### Chain Security analysis

See [this gist](https://gist.github.com/ritzdorf/1c6bd72955391e831f8a397d3152b4e0), with the following comment:

> The first two occur very frequently, the others are less frequent. We listed the final one even though it would still work the EIP as we are not sure how these gas values are currently being determined for such "deep" transactions. We wanted to raise awareness of potential issues.

#### Kyber Network

```
    function() public payable {
        require(reserveType[msg.sender] != ReserveType.NONE);
        EtherReceival(msg.sender, msg.value);
    }
```

- KyberNetwork meets several of the criterias, 
 - Implements the "Designated senders" pattern, 
 - Called primarily through other contracts, which rely on `transfer` (this limited to `2300` gas)

We reached out to Kyber Netwrok, and although it is obviously a chore to do, this can be solved: 

 > technically the market maker can just deploy new reserve contract

#### CappedVault

```
    function total() public view returns(uint) {
        return getBalance() + withdrawn;
    }

    function () public payable {
        require(total() + msg.value <= limit);
    }
```
In this context, `withdrawn` is a storage `slot`, and so is `limit`. 

- CappedVault, with over `4K ether` and `70K` internal transactions, meet the criteria:
  - Implements the "Limited" pattern
  - Two `SLOAD` and one `BALANCE`

Implementation note: 

- This contract is programmed to 'break' exactly like this, in case the total of ether passed through the contract exceeds `33333 ether`. That is, regardless of how much `ether` is currently in the vault, it will cease to accept `ether` after `33K` has passed through it. 
  - **This indicates that there already _must_ be mechanisms to handle the case when `default` cease functioning. **
- The `limit` is a storage `slot`, but could have been implemented as a compile-time constant, reducing one `SLOAD`. 
- The `balance(self)` could, after Istanbul, be rewritten as `SELFBALANCE`

In essence, it currently uses:

 `200 (sload limit) +200 (sload withdrawn) +400 (balance) = 800 gas` 

into, post-EIp-1884: 

`5 (selfbalance) + 800 (sload withdrawn) = 805 gas`. 


