const {
    getDatabase,
    getClient,
    USERS_COLLECTION,
    TRANSACTIONS_COLLECTION
} = require("../database/honeypotmongodb");

function valueFrom(document, names, fallback = "") {
    for (const name of names) {
        if (document?.[name] !== undefined && document?.[name] !== null) {
            return document[name];
        }
    }
    return fallback;
}

function usernameOf(user) {
    return String(valueFrom(user, ["username", "userName", "name"], "Unknown"));
}

function accountNumberOf(user) {
    return String(valueFrom(user, ["accountNumber", "account_number", "account"], ""));
}

function balanceFieldOf(user) {
    if (Object.prototype.hasOwnProperty.call(user, "balance")) return "balance";
    if (Object.prototype.hasOwnProperty.call(user, "bankBalance")) return "bankBalance";
    if (Object.prototype.hasOwnProperty.call(user, "bank_balance")) return "bank_balance";
    return "balance";
}

function balanceOf(user) {
    return Number(valueFrom(user, ["balance", "bankBalance", "bank_balance"], 0));
}

function publicTransaction(transaction, currentUser) {
    const currentId = String(currentUser._id);
    const currentUsername = usernameOf(currentUser);

    const senderId = String(valueFrom(transaction, ["senderId", "fromUserId", "sender_id"], ""));
    const senderUsername = String(valueFrom(transaction,
        ["senderUsername", "fromUsername", "sender", "from"], ""));

    const recipientUsername = String(valueFrom(transaction,
        ["recipientUsername", "toUsername", "recipient", "to"], ""));

    const outgoing = senderId
        ? senderId === currentId
        : senderUsername === currentUsername;

    return {
        id: String(transaction._id),
        recipient: outgoing ? (recipientUsername || "Unknown") : (senderUsername || "Unknown"),
        amount: Number(valueFrom(transaction, ["amount", "transferAmount"], 0)),
        description: String(valueFrom(transaction, ["description", "note"], "")),
        status: String(valueFrom(transaction, ["status"], "Completed")),
        type: outgoing ? "Sent" : "Received",
        createdAt: valueFrom(transaction, ["createdAt", "date", "timestamp"], null)
    };
}

function transactionHistoryQuery(user) {
    const username = usernameOf(user);
    const accountNumber = accountNumberOf(user);
    const choices = [
        { senderId: user._id },
        { recipientId: user._id },
        { fromUserId: user._id },
        { toUserId: user._id },
        { senderUsername: username },
        { recipientUsername: username },
        { fromUsername: username },
        { toUsername: username },
        { sender: username },
        { recipient: username },
        { from: username },
        { to: username }
    ];

    if (accountNumber) {
        choices.push(
            { senderAccountNumber: accountNumber },
            { recipientAccountNumber: accountNumber },
            { fromAccount: accountNumber },
            { toAccount: accountNumber }
        );
    }

    return { $or: choices };
}

function recipientQuery(input) {
    return {
        $or: [
            { username: input },
            { userName: input },
            { name: input },
            { accountNumber: input },
            { account_number: input },
            { account: input }
        ]
    };
}

async function getDashboardData(req, res, next) {
    try {
        const db = getDatabase();

        console.log("Honeypot database:", db.databaseName);
        console.log("Users collection:", USERS_COLLECTION);
        console.log("Authenticated user from middleware:", req.user);

        const user = await db.collection(USERS_COLLECTION).findOne({ _id: req.user._id });

        console.log("User loaded for dashboard:", user);
        console.log("Detected balance field:", balanceFieldOf(user));
        console.log("Detected balance value:", balanceOf(user));
        
        const transactions = await db.collection(TRANSACTIONS_COLLECTION)
            .find(transactionHistoryQuery(user))
            .sort({ createdAt: -1, date: -1, timestamp: -1, _id: -1 })
            .limit(50)
            .toArray();

        res.json({
            user: {
                username: usernameOf(user),
                accountNumber: accountNumberOf(user),
                balance: balanceOf(user)
            },
            transactions: transactions.map(item => publicTransaction(item, user))
        });
    } catch (error) {
        next(error);
    }
}

async function transferMoney(req, res, next) {
    const db = getDatabase();
    const mongoSession = getClient().startSession();

    try {
        const recipientInput = String(req.body.recipient || "").trim();
        const amount = Number(req.body.amount);
        const description = String(req.body.description || "").trim().slice(0, 200);

        if (!recipientInput) return res.status(400).json({ message: "Recipient is required" });
        if (!Number.isFinite(amount) || amount <= 0) {
            return res.status(400).json({ message: "Amount must be greater than zero" });
        }

        const normalizedAmount = Math.round(amount * 100) / 100;
        if (normalizedAmount !== amount) {
            return res.status(400).json({ message: "Amount can have at most two decimal places" });
        }

        let responseData;

        const runTransfer = async (sessionOptions = {}) => {
            const users = db.collection(USERS_COLLECTION);
            const transactions = db.collection(TRANSACTIONS_COLLECTION);

            const sender = await users.findOne({ _id: req.user._id }, sessionOptions);
            const recipient = await users.findOne(recipientQuery(recipientInput), sessionOptions);

            if (!sender) throw Object.assign(new Error("Sender account was not found"), { status: 404 });
            if (!recipient) throw Object.assign(new Error("Recipient account was not found"), { status: 404 });
            if (String(recipient._id) === String(sender._id)) {
                throw Object.assign(new Error("You cannot transfer money to your own account"), { status: 400 });
            }

            const senderBalanceField = balanceFieldOf(sender);
            const recipientBalanceField = balanceFieldOf(recipient);

            const debit = await users.updateOne(
                {
                    _id: sender._id,
                    [senderBalanceField]: { $gte: normalizedAmount }
                },
                { $inc: { [senderBalanceField]: -normalizedAmount } },
                sessionOptions
            );

            if (debit.modifiedCount !== 1) {
                throw Object.assign(new Error("Insufficient balance"), { status: 400 });
            }

            const credit = await users.updateOne(
                { _id: recipient._id },
                { $inc: { [recipientBalanceField]: normalizedAmount } },
                sessionOptions
            );

            if (credit.modifiedCount !== 1) {
                throw new Error("Could not update the recipient balance");
            }

            const transaction = {
                senderId: sender._id,
                senderUsername: usernameOf(sender),
                senderAccountNumber: accountNumberOf(sender),
                recipientId: recipient._id,
                recipientUsername: usernameOf(recipient),
                recipientAccountNumber: accountNumberOf(recipient),
                amount: normalizedAmount,
                description,
                status: "Completed",
                createdAt: new Date()
            };

            const inserted = await transactions.insertOne(transaction, sessionOptions);
            const updatedSender = await users.findOne({ _id: sender._id }, sessionOptions);

            responseData = {
                message: "Transfer completed successfully",
                balance: balanceOf(updatedSender),
                transaction: publicTransaction(
                    { ...transaction, _id: inserted.insertedId },
                    sender
                )
            };
        };

        await mongoSession.withTransaction(async () => {
            await runTransfer({ session: mongoSession });
        });

        res.json(responseData);
    } catch (error) {
        if (error.status) return res.status(error.status).json({ message: error.message });
        next(error);
    } finally {
        await mongoSession.endSession();
    }
}

module.exports = { getDashboardData, transferMoney };
