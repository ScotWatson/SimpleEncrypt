/*
(c) 2022 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

"use strict";

const initPageTime = performance.now();

const loadWindow = new Promise(function (resolve, reject) {
  window.addEventListener("load", function (evt) {
    resolve(evt);
  });
});

const loadErrorLogModule = (async function () {
  try {
    const module = await import("https://scotwatson.github.io/Debug/ErrorLog.mjs");
    return module;
  } catch (e) {
    console.error(e);
  }
})();

const loadEncryptionModule = (async function () {
  try {
    const module = await import("https://scotwatson.github.io/WebCrypto/Crypto.mjs");
    return module;
  } catch (e) {
    console.error(e);
  }
})();

(async function () {
  try {
    const modules = await Promise.all( [ loadWindow, loadErrorLogModule, loadEncryptionModule ] );
    start(modules);
  } catch (e) {
    console.error(e);
  }
})();

let btnEncryptText;
let btnDecryptText;
let btnEncryptFile;
let btnDecryptFile;
let plaintextEntry;

async function start( [ evtWindow, ErrorLog, Encryption ] ) {
  async function encryptText() {
    const password = prompt("Password:");
    if (password === null) {
      return;
    }
    const encoder = new TextEncoder("utf-8");
    const passwordBytes = encoder.encode(password);
    const key = await Encryption.digest_SHA256(passwordBytes);
    const plaintextBytes = encoder.encode(plaintextEntry.value);
    const encrypted = await Encryption.encrypt_AES256_CBC({
      plaintext: plaintextBytes,
      key: key,
    });
    saveFile(new Blob( [ encrypted.iv, encrypted.ciphertext ] ));
  }
  async function decryptText() {
    const file = await openFile();
    const fileBytes = await file.arrayBuffer();
    const iv = new Uint8Array(fileBytes, 0, 16);
    const ciphertext = new Uint8Array(fileBytes, 16);
    const password = prompt("Password:");
    if (password === null) {
      return;
    }
    const encoder = new TextEncoder("utf-8");
    const passwordBytes = encoder.encode(password);
    const key = await Encryption.digest_SHA256(passwordBytes);
    console.log({
      ciphertext: ciphertext,
      key: key,
      iv: iv,
    });
    const decrypted = await Encryption.decrypt_AES256_CBC({
      ciphertext: ciphertext,
      key: key,
      iv: iv,
    });
    const decoder = new TextDecoder("utf-8");
    plaintextEntry.value = decoder.decode(decrypted);
  }
  async function encryptFile() {
    const file = await openFile();
    const plaintextBytes = await file.arrayBuffer();
    const password = prompt("Password:");
    if (password === null) {
      return;
    }
    const encoder = new TextEncoder("utf-8");
    const passwordBytes = encoder.encode(password);
    const key = await Encryption.digest_SHA256(passwordBytes);
    const encrypted = await Encryption.encrypt_AES256_CBC({
      plaintext: plaintextBytes,
      key: key,
    });
    saveFile(new Blob( [ encrypted.iv, encrypted.ciphertext ] ));
  }
  async function decryptFile() {
    const file = await openFile();
    const fileBytes = await file.arrayBuffer();
    const iv = new Uint8Array(fileBytes, 0, 16);
    const ciphertext = new Uint8Array(fileBytes, 16);
    const password = prompt("Password:");
    if (password === null) {
      return;
    }
    const encoder = new TextEncoder("utf-8");
    const passwordBytes = encoder.encode(password);
    const key = await Encryption.digest_SHA256(passwordBytes);
    const decrypted = await Encryption.decrypt_AES256_CBC({
      ciphertext: ciphertext,
      key: key,
      iv: iv,
    });
    saveFile(new Blob( [ decrypted ] ));
  }
  try {
    document.body.style.overflow = "hidden";
    const pButtons = document.createElement("p");
    document.body.appendChild(pButtons);
    btnEncryptText = document.createElement("button");
    btnEncryptText.innerHTML = "Encrypt Text";
    btnEncryptText.addEventListener("click", function (evt) {
      encryptText();
    });
    pButtons.appendChild(btnEncryptText);
    btnDecryptText = document.createElement("button");
    btnDecryptText.innerHTML = "Decrypt Text";
    btnDecryptText.addEventListener("click", function (evt) {
      decryptText();
    });
    pButtons.appendChild(btnDecryptText);
    btnEncryptFile = document.createElement("button");
    btnEncryptFile.innerHTML = "Encrypt File";
    btnEncryptFile.addEventListener("click", function (evt) {
      encryptFile();
    });
    pButtons.appendChild(btnEncryptFile);
    btnDecryptFile = document.createElement("button");
    btnDecryptFile.innerHTML = "Decrypt File";
    btnDecryptFile.addEventListener("click", function (evt) {
      decryptFile();
    });
    pButtons.appendChild(btnDecryptFile);
    plaintextEntry = document.createElement("textarea");
    plaintextEntry.style.height = "100%";
    plaintextEntry.style.width = "100%";
    document.body.appendChild(plaintextEntry);
  } catch (e) {
    ErrorLog.rethrow({
      functionName: "start",
      error: e,
    });
  }
}

function openFile() {
  return new Promise(function (resolve, reject) {
    const inpFile = document.createElement("input");
    inpFile.type = "file";
    inpFile.addEventListener("input", function (evt) {
      resolve(inpFile.files[0]);
    });
    inpFile.click();
  });
}

function saveFile(blob) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
