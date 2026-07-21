const { MongoClient, ObjectId } = require("mongodb");

const BANK_DATABASE = process.env.BANK_DB || "Bank9111";
const USERS_COLLECTION = "users";
const TRANSACTIONS_COLLECTION = "transactions";

let client;
let database;

async function connectToDatabase() {
    if (database) return database;

    const uri = process.env.MONGO_URI;
    if (!uri) throw new Error("MONGO_URI must be defined in .env");

    client = new MongoClient(uri);
    await client.connect();
    database = client.db(BANK_DATABASE);

    // Non-unique indexes are safe with an already populated database.
    await Promise.allSettled([
        database.collection(USERS_COLLECTION).createIndex({ username: 1 }),
        database.collection(USERS_COLLECTION).createIndex({ accountNumber: 1 }),
        database.collection(TRANSACTIONS_COLLECTION).createIndex({ senderId: 1, createdAt: -1 }),
        database.collection(TRANSACTIONS_COLLECTION).createIndex({ recipientId: 1, createdAt: -1 })
    ]);

    console.log(`Connected to MongoDB: ${BANK_DATABASE}`);
    return database;
}

function getDatabase() {
    if (!database) throw new Error("Database has not been connected yet");
    return database;
}

function getClient() {
    if (!client) throw new Error("Database has not been connected yet");
    return client;
}

function toObjectId(id) {
    if (id instanceof ObjectId) return id;
    return ObjectId.isValid(id) ? new ObjectId(id) : id;
}

async function closeDatabase() {
    if (client) await client.close();
    client = undefined;
    database = undefined;
}

module.exports = {
    BANK_DATABASE,
    USERS_COLLECTION,
    TRANSACTIONS_COLLECTION,
    connectToDatabase,
    getDatabase,
    getClient,
    toObjectId,
    closeDatabase
};
