const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken'); // Для декодування IdToken

// Ініціалізація AWS сервісів з регіоном із змінних оточення
const cognito = new AWS.CognitoIdentityServiceProvider({
    region: process.env.region
});
const dynamodb = new AWS.DynamoDB.DocumentClient({
    region: process.env.region
});

// Змінні оточення
const USER_POOL_ID = process.env.cup_id;
const CLIENT_ID = process.env.cup_client_id;
const TABLES_TABLE = process.env.tables_table;
const RESERVATIONS_TABLE = process.env.reservations_table;

// Регулярні вирази для валідації
const emailRegex = /^[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[$%^*\-_])[A-Za-z\d$%^*\-_]{12,}$/;

// Основний обробник Lambda
exports.handler = async (event) => {
    console.log("Received event:", JSON.stringify(event, null, 2));

    // Перевірка змінних оточення
    if (!USER_POOL_ID || !CLIENT_ID || !TABLES_TABLE || !RESERVATIONS_TABLE) {
        return formatResponse(500, { error: "Missing required environment variables" });
    }

    const method = event.httpMethod;
    const resource = event.resource;
    let body;

    try {
        body = event.body ? JSON.parse(event.body) : {};
    } catch (error) {
        return formatResponse(400, { error: "Invalid request body" });
    }

    // Обробка маршрутів
    try {
        // Signup: POST /signup
        if (resource === '/signup' && method === 'POST') {
            return await signUpUser(body.email, body.password, body.firstName, body.lastName);
        }

        // Signin: POST /signin
        if (resource === '/signin' && method === 'POST') {
            return await signInUser(body.email, body.password);
        }

        // Перевірка IdToken для захищених маршрутів
        const idToken = event.headers?.Authorization?.replace('Bearer ', '');
        const user = await verifyIdToken(idToken);
        if (!user && resource !== '/signup' && resource !== '/signin') {
            return formatResponse(401, { error: "Unauthorized: Invalid or missing IdToken" });
        }

        // Список столів: GET /tables
        if (resource === '/tables' && method === 'GET') {
            return await getTables();
        }

        // Створення стола: POST /tables
        if (resource === '/tables' && method === 'POST') {
            return await createTable(body);
        }

        // Отримання стола за ID: GET /tables/{tableId}
        if (resource === '/tables/{tableId}' && method === 'GET') {
            const tableId = event.pathParameters?.tableId;
            if (!tableId) return formatResponse(400, { error: "Missing tableId" });
            return await getTableById(tableId);
        }

        // Створення резервування: POST /reservations
        if (resource === '/reservations' && method === 'POST') {
            return await createReservation(body);
        }

        // Список резервувань: GET /reservations
        if (resource === '/reservations' && method === 'GET') {
            return await getReservations();
        }

        return formatResponse(404, { error: "Unsupported route" });
    } catch (error) {
        console.error("Handler error:", error);
        return formatResponse(500, { error: "Internal Server Error", details: error.message });
    }
};

// Уніфікована функція форматування відповіді
function formatResponse(statusCode, body) {
    return {
        statusCode,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
        },
        body: JSON.stringify(body)
    };
}

// Перевірка IdToken
async function verifyIdToken(idToken) {
    if (!idToken) return null;

    try {
        const decoded = jwt.decode(idToken);
        if (!decoded || decoded.iss !== `https://cognito-idp.${process.env.region}.amazonaws.com/${USER_POOL_ID}`) {
            console.error("Invalid IdToken issuer");
            return null;
        }
        // Перевірка через Cognito (опціонально, якщо потрібна повна валідація)
        // const params = { AccessToken: idToken };
        // await cognito.getUser(params).promise();
        return decoded;
    } catch (error) {
        console.error("IdToken verification error:", error);
        return null;
    }
}

// Функції для Cognito
async function signUpUser(email, password, firstName, lastName) {
    if (!email || !password || !firstName || !lastName) {
        return formatResponse(400, { error: "All fields are required" });
    }
    if (!emailRegex.test(email)) {
        return formatResponse(400, { error: "Invalid email format" });
    }
    if (!passwordRegex.test(password)) {
        return formatResponse(400, { error: "Invalid password format" });
    }

    const params = {
        ClientId: CLIENT_ID,
        Username: email,
        Password: password,
        UserAttributes: [
            { Name: 'email', Value: email },
            { Name: 'given_name', Value: firstName },
            { Name: 'family_name', Value: lastName }
        ]
    };

    try {
        await cognito.signUp(params).promise();
        await cognito.adminConfirmSignUp({
            UserPoolId: USER_POOL_ID,
            Username: email
        }).promise();
        return formatResponse(200, { message: "User signed up successfully" });
    } catch (error) {
        console.error("SignUp error:", error);
        if (error.code === "UsernameExistsException") {
            return formatResponse(400, { error: "User already exists" });
        }
        return formatResponse(500, { error: "Signup failed", details: error.message });
    }
}

async function signInUser(email, password) {
    if (!email || !password) {
        return formatResponse(400, { error: "Email and password are required" });
    }

    const params = {
        AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
        UserPoolId: USER_POOL_ID,
        ClientId: CLIENT_ID,
        AuthParameters: {
            USERNAME: email,
            PASSWORD: password
        }
    };

    try {
        const data = await cognito.adminInitiateAuth(params).promise();
        const authResult = data.AuthenticationResult;
        return formatResponse(200, {
            idToken: authResult.IdToken, // Основний токен для аутентифікації
            accessToken: authResult.AccessToken, // Для операцій із атрибутами
            refreshToken: authResult.RefreshToken, // Для оновлення токенів
            expiresIn: authResult.ExpiresIn // Час дії в секундах
        });
    } catch (error) {
        console.error("SignIn error:", error);
        if (error.code === "NotAuthorizedException" || error.code === "UserNotFoundException") {
            return formatResponse(400, { error: "Invalid email or password" });
        }
        return formatResponse(500, { error: "Signin failed", details: error.message });
    }
}

// Функції для столів
async function createTable({ id, number, places, isVip, minOrder }) {
    if (!id || !number || !places) {
        return formatResponse(400, { error: "id, number, and places are required" });
    }

    const params = {
        TableName: TABLES_TABLE,
        Item: { id, number, places, isVip, minOrder }
    };

    try {
        await dynamodb.put(params).promise();
        return formatResponse(200, { id });
    } catch (error) {
        console.error("CreateTable error:", error);
        return formatResponse(500, { error: "Failed to create table", details: error.message });
    }
}

async function getTables() {
    try {
        const data = await dynamodb.scan({ TableName: TABLES_TABLE }).promise();
        return formatResponse(200, { tables: data.Items });
    } catch (error) {
        console.error("GetTables error:", error);
        return formatResponse(500, { error: "Failed to get tables", details: error.message });
    }
}

async function getTableById(tableId) {
    const params = {
        TableName: TABLES_TABLE,
        Key: { id: tableId }
    };

    try {
        const data = await dynamodb.get(params).promise();
        if (!data.Item) {
            return formatResponse(404, { error: "Table not found" });
        }
        return formatResponse(200, data.Item);
    } catch (error) {
        console.error("GetTableById error:", error);
        return formatResponse(500, { error: "Failed to get table", details: error.message });
    }
}

// Функції для резервувань
async function createReservation({ tableNumber, clientName, phoneNumber, date, slotTimeStart, slotTimeEnd }) {
    if (!tableNumber || !clientName || !phoneNumber || !date || !slotTimeStart || !slotTimeEnd) {
        return formatResponse(400, { error: "All reservation fields are required" });
    }

    try {
        const table = await getTableByNumber(tableNumber);
        if (!table) {
            return formatResponse(400, { error: "Table number does not exist" });
        }

        const reservations = await getReservationsByTableNumber(tableNumber);
        const conflict = reservations.some(r => {
            const actualStart = new Date(`${r.date} ${r.slotTimeStart}`);
            const actualEnd = new Date(`${r.date} ${r.slotTimeEnd}`);
            const reqStart = new Date(`${date} ${slotTimeStart}`);
            const reqEnd = new Date(`${date} ${slotTimeEnd}`);
            return (actualStart <= reqStart && actualEnd >= reqStart) ||
                (actualStart <= reqEnd && actualEnd >= reqEnd);
        });

        if (conflict) {
            return formatResponse(400, { error: "Reservation time overlaps with existing reservation" });
        }

        const reservationId = uuidv4();
        const params = {
            TableName: RESERVATIONS_TABLE,
            Item: {
                id: reservationId,
                tableNumber,
                clientName,
                phoneNumber,
                date,
                slotTimeStart,
                slotTimeEnd
            }
        };

        await dynamodb.put(params).promise();
        return formatResponse(200, { reservationId });
    } catch (error) {
        console.error("CreateReservation error:", error);
        return formatResponse(500, { error: "Failed to create reservation", details: error.message });
    }
}

async function getReservations() {
    try {
        const data = await dynamodb.scan({ TableName: RESERVATIONS_TABLE }).promise();
        return formatResponse(200, { reservations: data.Items });
    } catch (error) {
        console.error("GetReservations error:", error);
        return formatResponse(500, { error: "Failed to get reservations", details: error.message });
    }
}

// Допоміжні функції для DynamoDB
async function getTableByNumber(number) {
    const data = await dynamodb.scan({ TableName: TABLES_TABLE }).promise();
    return data.Items.find(table => table.number === number);
}

async function getReservationsByTableNumber(tableNumber) {
    const data = await dynamodb.scan({ TableName: RESERVATIONS_TABLE }).promise();
    return data.Items.filter(r => r.tableNumber === tableNumber);
}