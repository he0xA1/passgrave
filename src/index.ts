#!/usr/bin/env node

import { Command } from "@commander-js/extra-typings";
import * as crypto from "crypto";
import { homedir } from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import * as argon2 from "argon2";
import readline from "node:readline/promises";

const commandLine = new Command()
  .name("passgrave")
  .description("A secure password manager - where passwords rest in peace")
  .version("1.0.0")
  .showSuggestionAfterError(true);

commandLine.command("create").summary("Create password grave").description("");

commandLine
  .command("get")
  .argument("<name>", "name of the password entry to retrieve")
  .summary("Retrieve a specific password")
  .description(
    "Get the complete password entry including username, password, and notes for the specified name"
  );

commandLine
  .command("update")
  .argument("<name>", "name of the password entry to update or create")
  .summary("Update password entry")
  .description("");

commandLine
  .command("insert")
  .argument("<name>", "name of the password entry to create")
  .summary("Create or update a password entry")
  .description(
    "Add a new password entry or update an existing one. You'll be prompted for username, password, and optional notes"
  );

commandLine
  .command("delete")
  .argument("<name>", "name of the password entry to delete")
  .summary("Delete a password entry")
  .description(
    "Permanently remove a password entry from the vault. This action cannot be undone"
  );

export interface Password {
  salt: string;
  iv: string;
  encryptedPassword: string;
  authTag: string;
  version: number;
}

export interface Item {
  name: string;
  website?: string;
  mail: string;
  password: Password;
  note: string;
  createdAt: number;
  updatedAt: number;
}

export interface Grave {
  version: number;
  items: Item[];
  createdAt: number;
  updatedAt: number;
}

const fatal = (message: string): never => {
  console.error(`error: ${message}`);
  process.exit(1);
};

export class Valut {
  static readonly vaultPath = path.join(homedir(), ".grave");
  static readonly fileName = "grave.json";
  static readonly filePath = path.join(this.vaultPath, this.fileName);

  constructor() {
    if (!fs.existsSync(Valut.filePath)) {
      fatal("vault file not found");
    }
  }

  public static create() {
    if (!fs.existsSync(Valut.vaultPath)) {
      fs.mkdirSync(Valut.vaultPath, { recursive: true });
    }

    if (!fs.existsSync(Valut.filePath)) {
      fs.writeFileSync(
        Valut.filePath,
        JSON.stringify({
          version: 1,
          items: [],
          createdAt: Date.now(),
          updatedAt: Date.now(),
        }),
        { encoding: "utf-8" }
      );
    }
  }

  public read(): Grave {
    const vaultContent = fs.readFileSync(Valut.filePath, "utf-8");
    try {
      const decodedContent = JSON.parse(vaultContent) as Grave;
      return decodedContent;
    } catch (err) {
      if (err instanceof Error) {
        fatal(err.message);
      }
      process.exit(1);
    }
  }

  public write(content: Grave): void {
    fs.writeFileSync(Valut.filePath, JSON.stringify(content, null, 2), {
      encoding: "utf-8",
    });
  }
}

class VaultManager {
  vault: Valut;
  vaultContent: Grave;

  constructor(vault: Valut) {
    this.vault = vault;
    this.vaultContent = this.vault.read();
  }

  findItem(name: string): { item: Item; index: number } {
    for (const [index, item] of this.vaultContent.items.entries()) {
      if (item.name === name) {
        return { item, index };
      }
    }
    throw new Error("name does not exists");
  }

  nameExists(name: string): boolean {
    for (const item of this.vaultContent.items) {
      if (item.name === name) {
        return true;
      }
    }
    return false;
  }

  getAllItem(): Item[] {
    return this.vaultContent.items;
  }

  insertItem(item: Item) {
    if (this.nameExists(item.name)) {
      fatal("this name already exists");
    }

    item.createdAt = Date.now();
    item.updatedAt = Date.now();
    this.vaultContent.items.push(item);
    this.vaultContent.updatedAt = Date.now();
    this.vault.write(this.vaultContent);
  }

  updateItem(newItem: Item) {
    if (this.nameExists(newItem.name)) {
      fatal("this name already exists");
    }

    try {
      const item = this.findItem(newItem.name);
      newItem.updatedAt = Date.now();
      this.vaultContent.items[item.index] = newItem;
      this.vaultContent.updatedAt = Date.now();
    } catch (err) {
      if (err instanceof Error) {
        fatal(err.message);
      }
    }
  }

  deleteItem(name: string) {
    try {
      const item = this.findItem(name);
      this.vaultContent.items.splice(item.index, 1);
      this.vaultContent.updatedAt = Date.now();
      this.vault.write(this.vaultContent);

      console.log(`item deleted succesfully`);
    } catch (err) {
      if (err instanceof Error) {
        fatal(err.message);
      }
    }
  }
}

export class CryptoEngine {
  static async securePassword(password: string, salt: Buffer): Promise<Buffer> {
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      hashLength: 32,
      timeCost: 3,
      parallelism: 4,
      raw: true,
      salt: salt,
    });
  }

  static async encrypt(
    plainPasword: string,
    masterPassword: string
  ): Promise<Password> {
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    const key = await this.securePassword(masterPassword, salt);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    let encryptedPassowrd = cipher.update(plainPasword, "utf-8", "base64");

    encryptedPassowrd += cipher.final("base64");

    return {
      encryptedPassword: encryptedPassowrd,
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      version: 1,
    };
  }

  static async decrypt(
    encryptedPassword: Password,
    masterPassword: string
  ): Promise<string> {
    const key = await this.securePassword(
      masterPassword,
      Buffer.from(encryptedPassword.salt, "base64")
    );

    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(encryptedPassword.iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(encryptedPassword.authTag, "base64"));

    let decyptedPassword = decipher.update(
      encryptedPassword.encryptedPassword,
      "base64",
      "utf-8"
    );
    decyptedPassword += decipher.final("utf-8");

    return decyptedPassword;
  }
}

export class Core {
  vaultManager: VaultManager;
  input = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  constructor(vaultManager: VaultManager) {
    this.vaultManager = vaultManager;
  }

  async insert(name: string) {
    if (this.vaultManager.nameExists(name)) {
      fatal("the name exists");
      return;
    }

    const password = await this.input.question("Password: ");
    const mail = await this.input.question("Mail: ");
    const website = await this.input.question("Website: ");
    const note = await this.input.question("Note: ");

    const masterPassword = await this.input.question("Encrypt With: ");

    const item: Item = {
      name: name,
      website: website,
      note: note,
      mail: mail,
      password: await CryptoEngine.encrypt(password, masterPassword),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    this.vaultManager.insertItem(item);
    console.log("Inserted Succesfully");
    this.input.close();
  }

  async get(name: string) {
    try {
      const masterPassword = await this.input.question("Dencrypt With: ");

      const { item } = this.vaultManager.findItem(name);

      console.log(
        `Website: ${item.website}\nMail: ${
          item.mail
        }\nPassword: ${await CryptoEngine.decrypt(
          item.password,
          masterPassword
        )}\nNote: ${item.note}`
      );
    } catch (err) {
      if (err instanceof Error) {
        fatal(err.message);
      }
    }
    this.input.close();
  }

  async delete(name: string) {
    this.vaultManager.deleteItem(name);
    this.input.close();
  }
}

async function main() {
  await commandLine.parseAsync(process.argv);
  const executedCommand = commandLine.commands.find((cmd) =>
    process.argv.includes(cmd.name())
  );

  if (!executedCommand) {
    fatal("comman not found");
    return;
  }

  const commandName = executedCommand?.name();
  const commandArgs = executedCommand.args.at(0) || "";
  // const commandOpts = executedCommand.opts();
  if (commandName === "create") {
    Valut.create();
    console.log(`vault created at ${Valut.filePath}`);
    return;
  }

  const vault = new Valut();
  const vaultManager = new VaultManager(vault);
  const core = new Core(vaultManager);

  if (commandName === "insert") {
    await core.insert(commandArgs);
  } else if (commandName === "get") {
    await core.get(commandArgs);
  } else if (commandName === "delete") {
    await core.delete(commandArgs);
  }
}

main();
