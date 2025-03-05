let passwordStore = {};
function stringToBuffer(str) {
    return new TextEncoder().encode(str);
}

function bufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

function encodeBuffer(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function decodeBuffer(encoded) {
    return Uint8Array.from(atob(encoded), c => c.charCodeAt(0)).buffer;
}

async function deriveKey(masterPassword, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        stringToBuffer(masterPassword),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: stringToBuffer(salt),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        256
    );

    return {
        aesKey: await crypto.subtle.importKey(
            "raw",
            derivedBits,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        ),
        hmacKey: derivedBits 
    };
}

async function encryptData(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        stringToBuffer(data)
    );
    return { iv: encodeBuffer(iv), encryptedData: encodeBuffer(encrypted) };
}

async function decryptData(key, encryptedData, iv) {
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: decodeBuffer(iv) },
        key,
        decodeBuffer(encryptedData)
    );
    return bufferToString(decrypted);
}

async function hashDomain(domain, hmacKey) {
    const hmacKeyImported = await crypto.subtle.importKey(
        "raw",
        hmacKey,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        hmacKeyImported,
        stringToBuffer(domain)
    );

    return encodeBuffer(signature);
}

async function storePassword(domain, password, masterPassword, salt) {
    const { aesKey, hmacKey } = await deriveKey(masterPassword, salt);
    const encrypted = await encryptData(aesKey, password);
    const hashedDomain = await hashDomain(domain, hmacKey);
    passwordStore[hashedDomain] = encrypted;
}

async function retrievePassword(domain, masterPassword, salt) {
    const { aesKey, hmacKey } = await deriveKey(masterPassword, salt);
    const hashedDomain = await hashDomain(domain, hmacKey);
    const encrypted = passwordStore[hashedDomain];
    if (encrypted) {
        return await decryptData(aesKey, encrypted.encryptedData, encrypted.iv);
    }
    return null;
}

// Test
const masterPassword = "myMasterPassword";
const salt = "someRandomSalt";

storePassword("example.com", "myPassword123", masterPassword, salt)
    .then(() => retrievePassword("example.com", masterPassword, salt))
    .then(decryptedPassword => {
        console.log("Decrypted Password:", decryptedPassword);
    })
    .catch(err => {
        console.error("Error:", err);
    });
