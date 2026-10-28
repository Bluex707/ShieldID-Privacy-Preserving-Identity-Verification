// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IssuerRegistry
/// @notice Minimal trust registry: maps an issuer id (e.g. a domain-style name)
///         to the issuer's current public key, so verifiers can look keys up
///         without contacting the issuer.
///
/// Trust model
///  * The deployer is the registry `admin` (the "accreditation authority").
///    ONLY the admin can register an issuer id and assign its owner address.
///    Registration used to be open to everyone, which let anybody claim a name
///    such as "University_of_Jordan.edu.jo" before the real issuer did.
///  * Only the assigned owner can publish or revoke that issuer's key.
///  * Verifiers must still decide which issuers they trust (see
///    TRUSTED_ISSUER_IDS in config.py); a registry entry alone is not trust.
contract IssuerRegistry {
    address public immutable admin;

    mapping(string => string) private issuerKeys;
    mapping(string => address) private issuerOwner; // address(0) == not registered

    event IssuerRegistered(string issuerId, address indexed owner);
    event IssuerKeyPublished(string issuerId);
    event IssuerKeyRevoked(string issuerId);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "caller is not the registry admin");
        _;
    }

    modifier onlyIssuerOwner(string memory issuerId) {
        address registeredOwner = issuerOwner[issuerId];
        require(registeredOwner != address(0), "issuer not registered");
        require(registeredOwner == msg.sender, "caller is not the owner of this issuerId");
        _;
    }

    function registerIssuer(string memory issuerId, address owner) public onlyAdmin {
        require(owner != address(0), "owner is the zero address");
        uint256 len = bytes(issuerId).length;
        require(len > 0 && len <= 128, "invalid issuerId length");
        require(issuerOwner[issuerId] == address(0), "issuerId already registered");
        issuerOwner[issuerId] = owner;
        emit IssuerRegistered(issuerId, owner);
    }

    function publishIssuerKey(string memory issuerId, string memory publicKeyPem)
        public
        onlyIssuerOwner(issuerId)
    {
        require(bytes(publicKeyPem).length <= 4096, "public key too large");
        issuerKeys[issuerId] = publicKeyPem;
        emit IssuerKeyPublished(issuerId);
    }

    function revokeIssuerKey(string memory issuerId) public onlyIssuerOwner(issuerId) {
        delete issuerKeys[issuerId];
        emit IssuerKeyRevoked(issuerId);
    }

    function getIssuerKey(string memory issuerId) public view returns (string memory) {
        return issuerKeys[issuerId];
    }

    function getIssuerOwner(string memory issuerId) public view returns (address) {
        return issuerOwner[issuerId];
    }
}
