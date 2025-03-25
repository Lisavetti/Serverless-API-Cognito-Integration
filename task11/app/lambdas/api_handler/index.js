const { DynamoDBClient, PutItemCommand, ScanCommand, GetItemCommand,} = require("@aws-sdk/client-dynamodb");
const { marshall, unmarshall } = require("@aws-sdk/util-dynamodb");
const { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminSetUserPasswordCommand, AdminInitiateAuthCommand, DescribeUserPoolCommand,} = require("@aws-sdk/client-cognito-identity-provider");
const { v4: uuidv4 } = require('uuid');

const region = process.env.region;
const ddbClient = new DynamoDBClient({ region });
const cognitoClient = new CognitoIdentityProviderClient({ region });

const errorResponse = (message, code = 400) => ({
    statusCode: code,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ error: message }),
});


const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const isValidPassword = (password) =>
    /^[A-Za-z0-9\$%\^*\-_]{12,}$/.test(password);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function checkUserPoolExists(userPoolId) {
    try {
        await cognitoClient.send(
            new DescribeUserPoolCommand({ UserPoolId: userPoolId }),
        );
        return true;
    } catch (err) {
        console.error("User pool check error:", err);
        return false;
    }
}

async function signUpUser(body) {
    const { firstName, lastName, email, password } = body;
    if (!firstName || !lastName || !email || !password) {
        return errorResponse("Missing required fields", 400);
    }
    if (!isValidEmail(email)) {
        return errorResponse("Invalid email format", 400);
    }
    if (!isValidPassword(password)) {
        return errorResponse(
            "Invalid password format. Must be at least 12 characters long and include only alphanumeric characters and any of $%^*-_",
            400,
        );
    }
    const userPoolId = process.env.cup_id;
    const clientId = process.env.cup_client_id;
    if (!userPoolId || !clientId) {
        return errorResponse("Cognito configuration missing", 500);
    }
    let exists = await checkUserPoolExists(userPoolId);
    if (!exists) {
        let attempts = 3;
        while (attempts > 0 && !exists) {
            await sleep(5000);
            exists = await checkUserPoolExists(userPoolId);
            attempts--;
        }
        if (!exists) {
            return errorResponse(
                "User pool does not exist. Check your configuration.",
                500,
            );
        }
    }
    let retries = 3;
    while (retries > 0) {
        try {
            const createUserCmd = new AdminCreateUserCommand({
                UserPoolId: userPoolId,
                Username: email,
                UserAttributes: [
                    { Name: "given_name", Value: firstName },
                    { Name: "family_name", Value: lastName },
                    { Name: "email", Value: email },
                    { Name: "email_verified", Value: "true" },
                ],
                TemporaryPassword: password,
                MessageAction: "SUPPRESS",
            });
            await cognitoClient.send(createUserCmd);
            break;
        } catch (err) {
            if (err.name === "ResourceNotFoundException") {
                console.error(
                    "Retrying AdminCreateUserCommand due to propagation delay:",
                    err,
                );
                retries--;
                await sleep(5000);
            } else {
                console.error("Signup error:", err);
                return errorResponse("Signing up failed: " + err.message, 400);
            }
        }
    }
    if (retries === 0) {
        return errorResponse("Signing up failed: User pool not available", 400);
    }
    try {
        const setPasswordCmd = new AdminSetUserPasswordCommand({
            UserPoolId: userPoolId,
            Username: email,
            Password: password,
            Permanent: true,
        });
        await cognitoClient.send(setPasswordCmd);
        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: "User signed up successfully" }),
        };
    } catch (err) {
        console.error("Set password error:", err);
        return errorResponse("Signing up failed: " + err.message, 400);
    }
}

async function signInUser(body) {
    const { email, password } = body;
    if (!email || !password) {
        return errorResponse("Missing email or password", 400);
    }
    if (!isValidEmail(email)) {
        return errorResponse("Invalid email format", 400);
    }
    if (!isValidPassword(password)) {
        return errorResponse("Invalid password format", 400);
    }
    const userPoolId = process.env.cup_id;
    const clientId = process.env.cup_client_id;
    if (!userPoolId || !clientId) {
        return errorResponse("Cognito configuration missing", 500);
    }
    try {
        const authCmd = new AdminInitiateAuthCommand({
            AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
            UserPoolId: userPoolId,
            ClientId: clientId,
            AuthParameters: {
                USERNAME: email,
                PASSWORD: password,
            },
        });
        const data = await cognitoClient.send(authCmd);
        if (data.AuthenticationResult && data.AuthenticationResult.IdToken) {
            return {
                statusCode: 200,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ idToken: data.AuthenticationResult.IdToken }),
            };
        } else {
            return errorResponse("Authentication failed", 400);
        }
    } catch (err) {
        console.error("Signin error:", err);
        return errorResponse("Authentication failed: " + err.message, 400);
    }
}

async function getTables() {
    const tablesTable = process.env.tables_table;
    if (!tablesTable) return errorResponse("Tables table not configured", 500);
    try {
        const scanCmd = new ScanCommand({ TableName: tablesTable });
        const data = await ddbClient.send(scanCmd);
        const tables = data.Items
            ? data.Items.map((item) => {
                const table = unmarshall(item);
                if (table.id) {
                    table.id = Number(table.id);
                }
                return table;
            })
            : [];
        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ tables }),
        };
    } catch (err) {
        console.error("Get tables error:", err);
        return errorResponse("Failed to get tables: " + err.message, 400);
    }
}

async function createTable(body) {
    const { id, number, places, isVip, minOrder } = body;
    if (
        id === undefined ||
        number === undefined ||
        places === undefined ||
        isVip === undefined
    ) {
        return errorResponse("Missing required table fields", 400);
    }
    const tablesTable = process.env.tables_table;
    if (!tablesTable) return errorResponse("Tables table not configured", 500);
    const tableItem = {
        id: id.toString(),
        number,
        places,
        isVip,
    };
    if (minOrder !== undefined) {
        tableItem.minOrder = minOrder;
    }
    try {
        const putCmd = new PutItemCommand({
            TableName: tablesTable,
            Item: marshall(tableItem),
        });
        await ddbClient.send(putCmd);
        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: Number(tableItem.id) }),
        };
    } catch (err) {
        console.error("Create table error:", err);
        return errorResponse("Failed to create table: " + err.message, 400);
    }
}

async function getTableById(tableId) {
    if (!tableId) return errorResponse("Missing tableId", 400);
    const tablesTable = process.env.tables_table;
    if (!tablesTable) return errorResponse("Tables table not configured", 500);
    try {
        const getCmd = new GetItemCommand({
            TableName: tablesTable,
            Key: marshall({ id: tableId.toString() }),
        });
        const data = await ddbClient.send(getCmd);
        if (!data.Item) return errorResponse("Table not found", 400);
        const table = unmarshall(data.Item);
        if (table.id) {
            table.id = Number(table.id);
        }
        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(table),
        };
    } catch (err) {
        console.error("Get table by id error:", err);
        return errorResponse("Failed to get table: " + err.message, 400);
    }
}

function parseTime(timeStr) {
    const [hour, minute] = timeStr.split(":").map(Number);
    return hour * 60 + minute;
}

async function createReservation(body) {
    const {
        tableNumber,
        clientName,
        phoneNumber,
        date,
        slotTimeStart,
        slotTimeEnd,
    } = body;
    if (
        tableNumber === undefined ||
        !clientName ||
        !phoneNumber ||
        !date ||
        !slotTimeStart ||
        !slotTimeEnd
    ) {
        return errorResponse("Missing required reservation fields", 400);
    }
    // Check if the table exists based on tableNumber.
    const tablesTable = process.env.tables_table;
    const scanTablesCmd = new ScanCommand({
        TableName: tablesTable,
        FilterExpression: "#num = :tableNum",
        ExpressionAttributeNames: { "#num": "number" },
        ExpressionAttributeValues: { ":tableNum": { N: tableNumber.toString() } },
    });
    const tablesData = await ddbClient.send(scanTablesCmd);
    if (!tablesData.Items || tablesData.Items.length === 0) {
        return errorResponse("Table does not exist", 400);
    }
    // Check for overlapping reservations on the same table and date.
    const reservationsTable = process.env.reservations_table;
    const scanReservationsCmd = new ScanCommand({
        TableName: reservationsTable,
        FilterExpression: "#tbl = :tableNum and #d = :date",
        ExpressionAttributeNames: { "#tbl": "tableNumber", "#d": "date" },
        ExpressionAttributeValues: {
            ":tableNum": { N: tableNumber.toString() },
            ":date": { S: date },
        },
    });
    const reservationsData = await ddbClient.send(scanReservationsCmd);
    const newStart = parseTime(slotTimeStart);
    const newEnd = parseTime(slotTimeEnd);
    if (reservationsData.Items && reservationsData.Items.length > 0) {
        for (const item of reservationsData.Items) {
            const res = unmarshall(item);
            const existingStart = parseTime(res.slotTimeStart);
            const existingEnd = parseTime(res.slotTimeEnd);
            if (newStart < existingEnd && existingStart < newEnd) {
                return errorResponse(
                    "Reservation overlaps with existing reservation",
                    400,
                );
            }
        }
    }
    // Create reservation if no conflicts.
    const reservationId = uuidv4();
    const reservationItem = {
        id: reservationId,
        tableNumber,
        clientName,
        phoneNumber,
        date,
        slotTimeStart,
        slotTimeEnd,
    };
    try {
        const putCmd = new PutItemCommand({
            TableName: reservationsTable,
            Item: marshall(reservationItem),
        });
        await ddbClient.send(putCmd);
        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ reservationId }),
        };
    } catch (err) {
        console.error("Create reservation error:", err);
        return errorResponse("Failed to create reservation: " + err.message, 400);
    }
}

async function getReservations() {
    const reservationsTable = process.env.reservations_table;
    if (!reservationsTable)
        return errorResponse("Reservations table not configured", 500);
    try {
        const scanCmd = new ScanCommand({ TableName: reservationsTable });
        const data = await ddbClient.send(scanCmd);
        const reservations = data.Items
            ? data.Items.map((item) => unmarshall(item))
            : [];
        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ reservations }),
        };
    } catch (err) {
        console.error("Get reservations error:", err);
        return errorResponse("Failed to get reservations: " + err.message, 400);
    }
}

exports.handler = async (event) => {
    console.log("Received event:", JSON.stringify(event));
    const method = event.requestContext?.http?.method || event.httpMethod;
    const resource = event.resource;
    const authHeader =
        event.headers?.Authorization || event.headers?.authorization;
    let body;
    if (event.body) {
        try {
            body = JSON.parse(event.body);
        } catch (e) {
            return errorResponse("Invalid JSON body", 400);
        }
    }
    if (resource === "/signup" && method === "POST") {
        return await signUpUser(body);
    } else if (resource === "/signin" && method === "POST") {
        return await signInUser(body);
    } else if (resource === "/tables" && method === "GET") {
        if (!authHeader) return errorResponse("Unauthorized", 401);
        return await getTables();
    } else if (resource === "/tables" && method === "POST") {
        if (!authHeader) return errorResponse("Unauthorized", 401);
        return await createTable(body);
    } else if (resource === "/tables/{tableId}" && method === "GET") {
        if (!authHeader) return errorResponse("Unauthorized", 401);
        const tableId = event.pathParameters?.tableId;
        return await getTableById(tableId);
    } else if (resource === "/reservations" && method === "GET") {
        if (!authHeader) return errorResponse("Unauthorized", 401);
        return await getReservations();
    } else if (resource === "/reservations" && method === "POST") {
        if (!authHeader) return errorResponse("Unauthorized", 401);
        return await createReservation(body);
    } else {
        return errorResponse(
            `Unsupported resource: ${resource} with method ${method}`,
            400,
        );
    }
};