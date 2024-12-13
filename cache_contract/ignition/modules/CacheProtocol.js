const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

// npx hardhat ignore
module.exports = buildModule("CacheProtocol", (m) => {
  const contract = m.contract("CacheProtocol", ["0x636b7E4E9b7331047b431179809F3546e1f7A841"]);

  return { contract };
});