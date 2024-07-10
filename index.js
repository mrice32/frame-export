const crypto = require("crypto");
const readline = require("readline");
const fs = require("fs");
const path = require("path");
const os = require("os");
const hdKey = require("hdkey");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const hashPassword = (password, salt) => {
  return crypto.scryptSync(password, salt, 32, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 36000000,
  });
};

const readSeedSigner = (signerId) => {
  const fpath = path.join(
    os.homedir(),
    "Library",
    "Application Support",
    "Frame",
    "signers",
    `${signerId}.json`
  );
  return JSON.parse(fs.readFileSync(fpath));
};

const exportSeedSignerAccount = (signerJson, password, index) => {
  if (signerJson.type === "seed") {
  let [salt, iv, encryptedSeed] = signerJson.encryptedSeed.split(":");

  salt = Buffer.from(salt, "hex");
  iv = Buffer.from(iv, "hex");
  encryptedSeed = Buffer.from(encryptedSeed, "hex");

  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    hashPassword(password, salt),
    iv
  );
  const decrypted = Buffer.concat([
    decipher.update(encryptedSeed),
    decipher.final(),
  ]);

  let key = hdKey.fromMasterSeed(Buffer.from(decrypted.toString(), "hex"));
  key = key.derive("m/44'/60'/0'/0/" + index.toString());
  return key.privateKey;

    } else if (signerJson.type === "ring") {

  let [salt, iv, encryptedSeed] = signerJson.encryptedKeys.split(":");
  
  salt = Buffer.from(salt, "hex");
  iv = Buffer.from(iv, "hex");
  encryptedSeed = Buffer.from(encryptedSeed, "hex");

  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    hashPassword(password, salt),
    iv
  );
  const decrypted = Buffer.concat([
    decipher.update(encryptedSeed),
    decipher.final(),
  ]);

  return decrypted.toString()

    } else {
        throw new Error("Unsupported type");
    }
};

const main = () => {
  const signer = readSeedSigner(
    process.env.SIGNER_ID
  );

  rl.question("Password: ", (password) => {
    rl.question("Index: ", (index) => {
      const pk = exportSeedSignerAccount(signer, password, index);
      console.log(pk.toString("hex"));
    });
  });
};

main();