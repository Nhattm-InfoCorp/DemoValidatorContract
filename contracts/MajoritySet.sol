//! Copyright 2017 Peter Czaban, Parity Technologies Ltd.
//!
//! Licensed under the Apache License, Version 2.0 (the "License");
//! you may not use this file except in compliance with the License.
//! You may obtain a copy of the License at
//!
//!     http://www.apache.org/licenses/LICENSE-2.0
//!
//! Unless required by applicable law or agreed to in writing, software
//! distributed under the License is distributed on an "AS IS" BASIS,
//! WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//! See the License for the specific language governing permissions and
//! limitations under the License.

pragma solidity ^0.4.15;

import "./interfaces/ValidatorSet.sol";
import "./libraries/AddressVotes.sol";

// Existing validators can give support to addresses.
// Support can not be added once MAX_VALIDATORS are present.
// Once given, support can be removed.
// Addresses supported by more than half of the existing validators are the validators.
// Malicious behaviour causes support removal.
// Benign misbehaviour causes supprt removal if its called again after MAX_INACTIVITY.
// Benign misbehaviour can be absolved before being called the second time.

contract MajoritySet is ValidatorSet {
	// EVENTS
	event Report(address indexed reporter, address indexed reported, bytes indexed proof);
	event Support(address indexed supporter, address indexed supported, bool indexed added);
	event ChangeFinalized(address[] current_set);

	struct ValidatorStatus {
		// Is this a validator.
		bool isValidator;
		// Index in the validatorList.
		uint index;
		// Validator addresses which supported the address.
		AddressVotes.Data support;
		// Keeps track of the votes given out while the address is a validator.
		AddressVotes.Data supported;
		// Initial benign misbehaviour time tracker.
		mapping(address => uint) firstBenign;
		// Repeated benign misbehaviour counter.
		AddressVotes.Data benignMisbehaviour;
	}

	// System address, used by the block sealer.
	address constant SYSTEM_ADDRESS = 0xfffffffffffffffffffffffffffffffffffffffe;
// 	address constant SYSTEM_ADDRESS = 0xA328d644D1C45E9c6ebC892b3fEa9DA7937e71DC;
	// Support can not be added once this number of validators is reached.
	uint public constant MAX_VALIDATORS = 30;
	// Time after which the validators will report a validator as malicious.
	uint public constant MAX_INACTIVITY = 6 hours;
	// Ignore misbehaviour older than this number of blocks.
	uint public constant RECENT_BLOCKS = 20;

// STATE

	// Current list of addresses entitled to participate in the consensus.
	address[] public validatorsList;
	// Pending list of validator addresses.
	address[] pendingList;
	// Was the last validator change finalized.
	bool public finalized;
	// Tracker of status for each address.
	mapping(address => ValidatorStatus) validatorsStatus;

	// Used to lower the constructor cost.
	AddressVotes.Data initialSupport;

	// Each validator is initially supported by all others.
	function MajoritySet() public {
	    
	    pendingList.push(0xCA35b7d915458EF540aDe6068dFe2F44E8fa733c);
// 		pendingList.push(0xA328d644D1C45E9c6ebC892b3fEa9DA7937e71DC);
// 		pendingList.push(0x4B0897b0513fdC7C541B6d9D7E929C4e5364D2dB);
// 		pendingList.push(0x583031D1113aD414F02576BD6afaBfb302140225);

		for (uint i = 0; i < pendingList.length; i++) {
			address supporter = pendingList[i];
			AddressVotes.insert(initialSupport, supporter);
			validatorsStatus[supporter].isValidator = true;
			validatorsStatus[supporter].index = i;
			AddressVotes.insert(validatorsStatus[supporter].support, supporter);
			AddressVotes.insert(validatorsStatus[supporter].supported, supporter);
		}
		
		validatorsList = pendingList;
		finalized = true;
	}
	
	function getInitialSupport() external view returns (address[]){
	    AddressVotes.get(initialSupport);
	}

	// Called on every block to update node validator list.
	function getValidators() public constant returns (address[]) {
		return validatorsList;
	}

	// Log desire to change the current list.
	function initiateChange() private when_finalized {
		finalized = false;
		emit InitiateChange(block.blockhash(block.number - 1), pendingList);
	}

	function finalizeChange() public only_system_and_not_finalized {
		validatorsList = pendingList;
		finalized = true;
		emit ChangeFinalized(validatorsList);
	}

	// SUPPORT LOOKUP AND MANIPULATION

	// Find the total support for a given address.
	function getSupport(address validator) public constant returns (address[]) {
		return AddressVotes.get(validatorsStatus[validator].support);
	}

	function getSupported(address validator) public constant returns (address[]) {
		return AddressVotes.get(validatorsStatus[validator].supported);
	}

	// Vote to include a validator.
	function addSupport(address validator) public only_validator not_voted(validator) free_validator_slots {
		newStatus(validator);
		AddressVotes.insert(validatorsStatus[validator].support, msg.sender);
		AddressVotes.insert(validatorsStatus[msg.sender].supported, validator);
		addValidator(validator);
		emit Support(msg.sender, validator, true);
	}

	// Remove support for a validator.
	function removeSupport(address sender, address validator) private {
		require(AddressVotes.remove(validatorsStatus[validator].support, sender));
		emit Support(sender, validator, false);
		// Remove validator from the list if there is not enough support.
		removeValidator(validator);
	}

	// MALICIOUS BEHAVIOUR HANDLING

	// Called when a validator should be removed.
	function reportMalicious(address validator, uint blockNumber, bytes proof) public only_validator is_recent(blockNumber) {
		removeSupport(msg.sender, validator);
		emit Report(msg.sender, validator, proof);
	}

	// BENIGN MISBEHAVIOUR HANDLING

	// Report that a validator has misbehaved in a benign way.
	function reportBenign(address validator, uint blockNumber) public only_validator is_validator(validator) is_recent(blockNumber) {
		firstBenign(validator);
		repeatedBenign(validator);
		emit Report(msg.sender, validator, "Benign");
	}

	// Find the total number of repeated misbehaviour votes.
	function getRepeatedBenign(address validator) public constant returns (uint) {
		return AddressVotes.count(validatorsStatus[validator].benignMisbehaviour);
	}

	// Track the first benign misbehaviour.
	function firstBenign(address validator) private has_not_benign_misbehaved(validator) {
		validatorsStatus[validator].firstBenign[msg.sender] = now;
	}

	// Report that a validator has been repeatedly misbehaving.
	function repeatedBenign(address validator) private has_repeatedly_benign_misbehaved(validator) {
		AddressVotes.insert(validatorsStatus[validator].benignMisbehaviour, msg.sender);
		confirmedRepeatedBenign(validator);
	}

	// When enough long term benign misbehaviour votes have been seen, remove support.
	function confirmedRepeatedBenign(address validator) private agreed_on_repeated_benign(validator) {
		validatorsStatus[validator].firstBenign[msg.sender] = 0;
		AddressVotes.remove(validatorsStatus[validator].benignMisbehaviour, msg.sender);
		removeSupport(msg.sender, validator);
	}

	// Absolve a validator from a benign misbehaviour.
	function absolveFirstBenign(address validator) public has_benign_misbehaved(validator) {
		validatorsStatus[validator].firstBenign[msg.sender] = 0;
		AddressVotes.remove(validatorsStatus[validator].benignMisbehaviour, msg.sender);
	}

	// PRIVATE UTILITY FUNCTIONS

	// Add a status tracker for unknown validator.
	function newStatus(address validator) private has_no_votes(validator) {
	    AddressVotes.Data memory empty;
		validatorsStatus[validator] = ValidatorStatus({
			isValidator: false,
			index: pendingList.length,
			support: empty,
			supported: empty,
			benignMisbehaviour: empty
		});
	}

	// ENACTMENT FUNCTIONS (called when support gets out of line with the validator list)

	// Add the validator if supported by majority.
	// Since the number of validators increases it is possible to some fall below the threshold.
	function addValidator(address validator) public is_not_validator(validator) has_high_support(validator) {
		validatorsStatus[validator].index = pendingList.length;
		pendingList.push(validator);
		validatorsStatus[validator].isValidator = true;
		AddressVotes.insert(validatorsStatus[validator].support, validator);
		AddressVotes.insert(validatorsStatus[validator].supported, validator);
		initiateChange();
	}

	// Remove a validator without enough support.
	// Can be called to clean low support validators after making the list longer.
	function removeValidator(address validator) public is_validator(validator) has_low_support(validator) {
		uint removedIndex = validatorsStatus[validator].index;
		// Can not remove the last validator.
		uint lastIndex = pendingList.length-1;
		address lastValidator = pendingList[lastIndex];
		// Override the removed validator with the last one.
		pendingList[removedIndex] = lastValidator;
		// Update the index of the last validator.
		validatorsStatus[lastValidator].index = removedIndex;
		delete pendingList[lastIndex];
		pendingList.length--;
		// Reset validator status.
		validatorsStatus[validator].index = 0;
		validatorsStatus[validator].isValidator = false;
		// Remove all support given by the removed validator.
		address[] memory toRemove = AddressVotes.get(validatorsStatus[validator].supported);
		for (uint i = 0; i < toRemove.length; i++) {
			removeSupport(validator, toRemove[i]);
		}
		delete validatorsStatus[validator].supported;
		initiateChange();
	}

	// MODIFIERS

	function highSupport(address validator) public constant returns (bool) {
		return getSupport(validator).length > pendingList.length/2;
	}

	function firstBenignReported(address reporter, address validator) public constant returns (uint) {
		return validatorsStatus[validator].firstBenign[reporter];
	}

	modifier has_high_support(address validator) {
		if (highSupport(validator)) { _; }
	}

	modifier has_low_support(address validator) {
		if (!highSupport(validator)) { _; }
	}

	modifier has_not_benign_misbehaved(address validator) {
		if (firstBenignReported(msg.sender, validator) == 0) { _; }
	}

	modifier has_benign_misbehaved(address validator) {
		if (firstBenignReported(msg.sender, validator) > 0) { _; }
	}

	modifier has_repeatedly_benign_misbehaved(address validator) {
		if (firstBenignReported(msg.sender, validator) - now > MAX_INACTIVITY) { _; }
	}

	modifier agreed_on_repeated_benign(address validator) {
		if (getRepeatedBenign(validator) > pendingList.length/2) { _; }
	}

	modifier free_validator_slots() {
		require(pendingList.length < MAX_VALIDATORS);
		_;
	}

	modifier only_validator() {
		require(validatorsStatus[msg.sender].isValidator);
		_;
	}

	modifier is_validator(address someone) {
		if (validatorsStatus[someone].isValidator) { _; }
	}

	modifier is_not_validator(address someone) {
		if (!validatorsStatus[someone].isValidator) { _; }
	}

	modifier not_voted(address validator) {
		require(!AddressVotes.contains(validatorsStatus[validator].support, msg.sender));
		_;
	}

	modifier has_no_votes(address validator) {
		if (AddressVotes.count(validatorsStatus[validator].support) == 0) { _; }
	}

	modifier is_recent(uint blockNumber) {
		require(block.number <= blockNumber + RECENT_BLOCKS);
		_;
	}

	modifier only_system_and_not_finalized() {
		require(msg.sender == SYSTEM_ADDRESS && !finalized);
		_;
	}

	modifier when_finalized() {
		require(finalized);
		_;
	}
}