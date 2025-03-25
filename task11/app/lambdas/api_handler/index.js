const { DynamoDBClient, PutItemCommand,   ScanCommand, GetItemCommand, } = require("@aws-sdk/client-dynamodb");
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken')
const { v4: uuidv4 } = require('uuid');
const { marshall, unmarshall } = require("@aws-sdk/util-dynamodb");

// Initialize AWS services
const region = process.env.region || "eu-west-1";
const dynamoDB = new DynamoDBClient({ region });
const cognito = new AWS.CognitoIdentityServiceProvider();

// Get configuration from environment variables
const USER_POOL_ID = process.env.cup_id;
const CLIENT_ID = process.env.cup_client_id;
const TABLES_TABLE = process.env.tables_table;
const RESERVATIONS_TABLE = process.env.reservations_table;

// Main handler function
exports.handler = async (event, context) => {
    console.log("Event:", JSON.stringify({
        path: event.path,
        httpMethod: event.httpMethod,
        headers: event.headers?.Authorization,
        body: event.body
    }));
    try {
        const { path, httpMethod } = event; // Используем path вместо resource
        const routes = {
            "POST /signup": handleSignup,
            "POST /signin": handleSignin,
            "GET /tables": handleGetTables,
            "POST /tables": handleCreateTable,
            "GET /tables/{tableId}": handleGetTableById,
            "GET /reservations": handleGetReservations,
            "POST /reservations": handleCreateReservation,
        };
        const routeKey = `${httpMethod} ${path}`;
        const response = routes[routeKey]
            ? await routes[routeKey](event)
            : {
                statusCode: 404,
                headers: corsHeaders(),
                body: JSON.stringify({ message: "Not Found" }),
            };
        return response;
    } catch (error) {
        console.error("Error:", error);
        return {
            statusCode: 500,
            headers: corsHeaders(),
            body: JSON.stringify({
                message: "Internal Server Error",
                error: error.message,
            }),
        };
    }
};

// Helper functions for CORS headers
function corsHeaders() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET',
        'Content-Type': 'application/json'
    };
}

// Helper function for formatting responses
function formatResponse(statusCode, body) {
    return {
        statusCode: statusCode,
        headers: corsHeaders(),
        body: JSON.stringify(body)
    };
}

// SignUp handler
async function handleSignup(event) {
    try {
        const { firstName, lastName, email, password } = event.body;
        if (!firstName || !lastName || !email || !password) {
            return formatResponse(400, { error: "All fields are required." });
        }
        if (!/^[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}$/.test(email)) {
            return formatResponse(400, { error: "Invalid email format." });
        }
        if (!/^(?=.*[A-Za-z])(?=.*\d)(?=.*[$%^*\-_])[A-Za-z\d$%^*\-_]{12,}$/.test(password)) {
            return formatResponse(400, { error: "Invalid password format." });
        }

        await cognito.adminCreateUser({
            UserPoolId: USER_POOL_ID,
            Username: email,
            UserAttributes: [
                { Name: "given_name", Value: firstName },
                { Name: "family_name", Value: lastName },
                { Name: "email", Value: email },
                { Name: "email_verified", Value: "true" }
            ],
            TemporaryPassword: password,
            MessageAction: "SUPPRESS",
        }).promise();

        await cognito.adminSetUserPassword({
            UserPoolId: USER_POOL_ID,
            Username: email,
            Password: password,
            Permanent: true
        }).promise();

        return formatResponse(200, { message: "User created successfully." });
    } catch (error) {
        console.error("Signup error:", error);
        if (error.code === "UsernameExistsException") {
            return formatResponse(400, { error: "Email already exists." });
        }
        return formatResponse(502, { error: "Signup failed.", details: error.message });
    }
}

// Signin Handler
async function handleSignin(event) {
    try {
        const { email, password } = event.body;
        const getUserParams = {
            UserPoolId: USER_POOL_ID,
            Filter: `email = "${email}"`,
            Limit: 1
        };
        const users = await cognito.listUsers(getUserParams).promise();
        if (!users.Users.length) {
            return formatResponse(400, { error: "User does not exist." });
        }
        const username = users.Users[0].Username;
        const params = {
            AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
            UserPoolId: USER_POOL_ID,
            ClientId: CLIENT_ID,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password
            }
        };
        const authResponse = await cognito.adminInitiateAuth(params).promise();
        return formatResponse(200, {
            idToken: authResponse.AuthenticationResult?.IdToken
        });
    } catch (error) {
        return formatResponse(400, { error: error.message });
    }
}

// Table View
async function handleGetTables(event) {
    console.log(event);
    try{
        if (event.httpMethod !== "GET") {
            return formatResponse(400, { error: "Use GET." });
        }

        const authHeader = event.headers.Authorization || event.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return formatResponse(400, { error: "Missing or invalid Authorization header" });
        }

        const idToken = authHeader.split(" ")[1];
        if (!idToken) {
            return formatResponse(400, { error: "Missing token" });
        }

        const payload = jwt.decode(idToken);
        console.log(payload);
        if (!payload) {
            return formatResponse(400, { error: "Invalid token format" });
        }

        const username = payload['cognito:username'];
        if (!username) {
            return formatResponse(400, { error: "Username not found in token" });
        }


        const scanCmd = new ScanCommand({ TableName: TABLES_TABLE });
        const data = await dynamoDB.send(scanCmd);

        const result = data.Items
            ? data.Items.map((item) => {
                const table = unmarshall(item);
                if (table.id) {
                    table.id = Number(table.id);
                }
                return table;
            })
            : [];

        return formatResponse(200, { result });
    } catch (error) {
        console.error("Error fetching tables:", error);
        return formatResponse(500, { message: "Internal Server Error" });
    }
}

// Create Tables
async function handleCreateTable(event) {
    try {
        if (event.httpMethod !== "POST") {
            return formatResponse(400, {error: "Метод не разрешен. Используйте POST."});
        }

        const authHeader = event.headers.Authorization || event.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return formatResponse(400, { error: "Missing or invalid Authorization header" });
        }

        const idToken = authHeader.split(" ")[1];
        if (!idToken) {
            return formatResponse(400, { error: "Missing token" });
        }

        const payload = jwt.decode(idToken);
        console.log(payload);
        if (!payload) {
            return formatResponse(400, { error: "Invalid token format" });
        }

        const username = payload['cognito:username'];
        if (!username) {
            return formatResponse(400, { error: "Username not found in token" });
        }

        const table = event.body;

        if (typeof table.number !== "number" ||
            typeof table.places !== "number" ||
            typeof table.isVip !== "boolean") {
            return formatResponse(400, {
                message: 'Table number, capacity, and location are required'
            });
        }

        let tableId = table.id || uuidv4();

        const tableData = {
            id: String(tableId),
            number: table.number,
            places: table.places,
            isVip: table.isVip,
            minOrder: table.minOrder ?? 0,
        };


        await dynamoDB.send(new PutItemCommand({
            TableName: TABLES_TABLE,
            Item: marshall(tableData),
        }));

        return formatResponse(200, {id: tableId});
    } catch (error) {
        console.error("Ошибка при создании стола:", error);
        return formatResponse(400, { error: error.message || "Не удалось создать стол" });
    }
}

async function handleGetTableById(event) {
    try {
        if (event.httpMethod !== "GET") {
            return formatResponse(400, { error: "Метод не разрешен. Используйте GET." });
        }

        const authHeader = event.headers.Authorization || event.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return formatResponse(400, { error: "Missing or invalid Authorization header" });
        }

        const idToken = authHeader.split(" ")[1];
        if (!idToken) {
            return formatResponse(400, { error: "Missing token" });
        }

        const payload = jwt.decode(idToken);
        console.log(payload);
        if (!payload) {
            return formatResponse(400, { error: "Invalid token format" });
        }

        const username = payload['cognito:username'];
        if (!username) {
            return formatResponse(400, { error: "Username not found in token" });
        }

        // Extract tableId from path or pathParameters
        let tableId;
        if (event.pathParameters && event.pathParameters.tableId) {
            tableId = event.pathParameters.tableId; // API Gateway proxy integration
        } else {
            // Fallback: parse from event.path (e.g., "/tables/4")
            const pathParts = event.path.split("/");
            tableId = pathParts[pathParts.length - 1];
        }

        if (!tableId || isNaN(tableId) || parseInt(tableId) <= 0) {
            return formatResponse(400, { error: "Отсутствует или некорректный tableId в параметрах пути" });
        }
        console.log("Fetching table with ID:", tableId);

        const getCmd = new GetItemCommand({
            TableName: TABLES_TABLE,
            Key: marshall({ id: tableId.toString() }),
        });
        const result = await dynamoDB.send(getCmd);


        if (!result.Item) {
            return formatResponse(404, { message: "Table not found" });
        }
        const table = {
            id: parseInt(result.Item.id, 10),
            number: result.Item.number,
            places: result.Item.places,
            isVip: result.Item.isVip,
            minOrder: result.Item.minOrder || 0,
        };

        return formatResponse(200, table);
    } catch (error) {
        console.error("Error fetching table by ID:", error);
        return formatResponse(500, { message: "Internal Server Error" });
    }
}

// View Reservation
async function handleGetReservations(event) {
    const authHeader = event.headers.Authorization || event.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return formatResponse(400, { error: "Missing or invalid Authorization header" });
    }

    const idToken = authHeader.split(" ")[1];
    if (!idToken) {
        return formatResponse(400, { error: "Missing token" });
    }

    const payload = jwt.decode(idToken);
    console.log(payload);
    if (!payload) {
        return formatResponse(400, { error: "Invalid token format" });
    }

    const username = payload['cognito:username'];
    if (!username) {
        return formatResponse(400, { error: "Username not found in token" });
    }


    if (!RESERVATIONS_TABLE)
        return formatResponse(500,{ error: "Reservations table not configured" });
    try {
        const scanCmd = new ScanCommand({ TableName: RESERVATIONS_TABLE });
        const data = await dynamoDB.send(scanCmd);
        const reservations = data.Items
            ? data.Items.map((item) => unmarshall(item))
            : [];
        return formatResponse(200, { reservations });
    } catch (err) {
        console.error("Get reservations error:", err);
        return formatResponse(400, err.message);
    }
}

// Create Reservation
async function handleCreateReservation(event) {
    try {
        const authHeader = event.headers.Authorization || event.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return formatResponse(400, { error: "Missing or invalid Authorization header" });
        }

        const idToken = authHeader.split(" ")[1];
        if (!idToken) {
            return formatResponse(400, { error: "Missing token" });
        }

        const payload = jwt.decode(idToken);
        console.log(payload);
        if (!payload) {
            return formatResponse(400, { error: "Invalid token format" });
        }

        const username = payload['cognito:username'];
        if (!username) {
            return formatResponse(400, { error: "Username not found in token" });
        }

        const body = event.body;
        console.log(body);
        const { tableNumber, clientName, phoneNumber, date, slotTimeStart, slotTimeEnd } = body;
        if (!tableNumber || !date || !slotTimeStart || !slotTimeEnd) {
            return formatResponse(400, {
                message: 'Table number, date, slotTimeStart, and slotTimeEnd are required'
            });
        }

        const scanTablesCmd = new ScanCommand({
            TableName: TABLES_TABLE,
            FilterExpression: "#num = :tableNum",
            ExpressionAttributeNames: { "#num": "number" },
            ExpressionAttributeValues: { ":tableNum": { N: tableNumber.toString() } },
        });

        const tablesData = await dynamoDB.send(scanTablesCmd);

        if (tablesData.Items.length === 0) {
            return formatResponse(400, { message: 'Table not found' });
        }


        const scanReservationsCmd = new ScanCommand({
            TableName: RESERVATIONS_TABLE,
            FilterExpression: "#tbl = :tableNum and #d = :date",
            ExpressionAttributeNames: { "#tbl": "tableNumber", "#d": "date" },
            ExpressionAttributeValues: {
                ":tableNum": { N: tableNumber.toString() },
                ":date": { S: date },
            },
        });

        const reservationsData = await dynamoDB.send(scanReservationsCmd);

        const newStart = parseTime(slotTimeStart);
        const newEnd = parseTime(slotTimeEnd);

        if (reservationsData.Items && reservationsData.Items.length > 0) {
            for (const item of reservationsData.Items) {
                const res = unmarshall(item);
                const existingStart = parseTime(res.slotTimeStart);
                const existingEnd = parseTime(res.slotTimeEnd);
                if (newStart < existingEnd && existingStart < newEnd) {
                    return formatResponse(400, { message: "Reservation overlaps with existing reservation"});
                }
            }
        }

        const reservationId = uidv4();
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
                TableName: RESERVATIONS_TABLE,
                Item: marshall(reservationItem),
            });
            await dynamoDB.send(putCmd);
            return formatResponse(200, {reservationId})
        } catch (err) {
            console.error("Create reservation error:", err);
            return formatResponse(400, "Failed to create reservation")
        }













        const table = tableResult.Items[0];
        const tableId = table.id;
        const reservationCheckParams = {
            TableName: RESERVATIONS_TABLE,
            FilterExpression: "tableId = :tableId AND #date = :date AND (#time BETWEEN :start AND :end OR :start BETWEEN #time AND slotTimeEnd)",
            ExpressionAttributeNames: {
                "#date": "date",
                "#time": "time"
            },
            ExpressionAttributeValues: {
                ":tableId": tableId,
                ":date": date,
                ":start": slotTimeStart,
                ":end": slotTimeEnd
            }
        };
        const existingReservations = await dynamodb.scan(reservationCheckParams).promise();
        if (existingReservations.Items.length > 0) {
            return formatResponse(400, {
                message: 'Table is already reserved for the selected date and time'
            });
        }
        const reservation = {
            id: uuidv4(),
            tableId: tableId,
            tableNumber: table.number,
            clientName: clientName,
            phoneNumber: phoneNumber,
            username: username,
            date: date,
            time: slotTimeStart,
            slotTimeEnd: slotTimeEnd,
            createdAt: new Date().toISOString()
        };
        const reservationParams = {
            TableName: RESERVATIONS_TABLE,
            Item: reservation
        };
        await dynamodb.put(reservationParams).promise();
        return formatResponse(200, {
            reservationId: reservation.id,
            message: 'Reservation created successfully'
        });
    } catch (error) {
        return formatResponse(500, { message: "Internal Server Error" });
    }
}


function parseTime(timeStr) {
    const [hour, minute] = timeStr.split(":").map(Number);
    return hour * 60 + minute;
}