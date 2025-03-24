const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');

// Получаем переменные окружения
const userPoolId = process.env.cup_id;
const clientId = process.env.cup_client_id;
const tablesTable = process.env.tables_table;
const reservationsTable = process.env.reservations_table;

const cognito = new AWS.CognitoIdentityServiceProvider();
const docClient = new AWS.DynamoDB.DocumentClient();

// Регулярные выражения для валидации email и пароля
const emailRegex = /^[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[$%^*\-_])[A-Za-z\d$%^*\-_]{12,}$/;

exports.handler = async (event) => {
    console.log("----- START HANDLER -----");
    console.log("Environment variables:", {
        CUPId: process.env.CUPId,
        CUPClientId: process.env.CUPClientId,
        tables_table: process.env.tables_table,
        reservations_table: process.env.reservations_table,
    });
    console.log("Event received:", JSON.stringify(event, null, 2));

    // Проверяем наличие обязательных переменных окружения
    if (!userPoolId || !clientId || !tablesTable || !reservationsTable) {
        const errorMsg = "Missing one or more environment variables (CUPId, CUPClientId, tables_table, reservations_table)";
        console.error(errorMsg);
        return formatResponse(500, { message: errorMsg });
    }

    // Проверяем наличие обязательных полей в event
    if (!event.path || !event.httpMethod) {
        console.error("Missing path or httpMethod in event!");
        return formatResponse(400, { message: "Invalid event: Missing path or httpMethod" });
    }

    const path = event.path;
    const method = event.httpMethod;
    console.log(`Routing: path = ${path}, method = ${method}`);

    try {
        // Signup: POST /signup
        if (path === '/signup' && method === 'POST') {
            console.log("Route: Signup");
            const body = JSON.parse(event.body);
            console.log("Signup body:", body);

            if (!body.firstName || !body.lastName || !body.email || !body.password) {
                console.error("Validation error: Missing fields");
                return formatResponse(400, { message: "All fields are required." });
            }
            if (!emailRegex.test(body.email)) {
                console.error("Validation error: Invalid email format");
                return formatResponse(400, { message: "Invalid email format." });
            }
            if (!passwordRegex.test(body.password)) {
                console.error("Validation error: Invalid password format");
                return formatResponse(400, { message: "Invalid password format." });
            }
            return await handleSignUp(body.email, body.password, body.firstName, body.lastName);
        }

        // Signin: POST /signin
        if (path === '/signin' && method === 'POST') {
            console.log("Route: Signin");
            const body = JSON.parse(event.body);
            console.log("Signin body:", body);
            return await handleSignIn(body.email, body.password);
        }

        // Получение списка столов: GET /tables
        if (path === '/tables' && method === 'GET') {
            console.log("Route: GET /tables");
            return await handleTableList();
        }

        // Создание стола: POST /tables
        if (path === '/tables' && method === 'POST') {
            console.log("Route: POST /tables");
            const body = JSON.parse(event.body);
            console.log("Create table body:", body);
            return await handleTableCreate(body);
        }

        // Получение стола по id: GET /tables/{tableId}
        if (typeof path === 'string' && path.startsWith('/tables/') && method === 'GET') {
            console.log("Route: GET /tables/{tableId}");
            let tableId;
            if (event.pathParameters && event.pathParameters.tableId) {
                tableId = event.pathParameters.tableId;
            } else {
                const parts = path.split('/');
                if (parts.length >= 3) {
                    tableId = parts[2];
                } else {
                    console.error("Unable to extract tableId from path:", path);
                    return formatResponse(400, { message: "Missing tableId in path" });
                }
            }
            console.log("Extracted TableId:", tableId);
            return await handleTableById(tableId);
        }

        // Создание бронирования: POST /reservations
        if (path === '/reservations' && method === 'POST') {
            console.log("Route: POST /reservations");
            const body = JSON.parse(event.body);
            console.log("Reservation creation body:", body);
            return await handleReservationCreate(body);
        }

        // Получение списка бронирований: GET /reservations
        if (path === '/reservations' && method === 'GET') {
            console.log("Route: GET /reservations");
            return await handleReservationList();
        }

        console.error("Unsupported route:", method, path);
        return formatResponse(404, { message: "Unsupported route" });
    } catch (err) {
        console.error("Error in handler:", err);
        return formatResponse(500, { message: "Internal Server Error", error: err.message });
    } finally {
        console.log("----- END HANDLER -----");
    }
};

function formatResponse(statusCode, body) {
    console.log(`Formatting response with status ${statusCode}`);
    return {
        statusCode: statusCode,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
        },
        body: JSON.stringify(body),
    };
}

// --------------------- SIGN UP & SIGN IN ----------------------------

const handleSignUp = async (email, password, firstName, lastName) => {
    console.log("handleSignUp called:", { email, firstName, lastName });
    const params = {
        UserPoolId: userPoolId,
        Username: email,
        TemporaryPassword: password,
        UserAttributes: [
            { Name: 'email', Value: email },
            { Name: 'given_name', Value: firstName },
            { Name: 'family_name', Value: lastName },
            { Name: 'email_verified', Value: 'true' },
        ],
        MessageAction: 'SUPPRESS',
    };

    try {
        console.log("Calling adminCreateUser with params:", params);
        await cognito.adminCreateUser(params).promise();
        console.log("User created successfully in Cognito");

        const signinResponse = await cognitoSignIn(email, password);
        console.log("Received signinResponse:", signinResponse);

        console.log("Responding to auth challenge NEW_PASSWORD_REQUIRED");
        await cognito.adminRespondToAuthChallenge({
            UserPoolId: userPoolId,
            ClientId: clientId,
            ChallengeName: 'NEW_PASSWORD_REQUIRED',
            Session: signinResponse.Session,
            ChallengeResponses: {
                USERNAME: email,
                PASSWORD: password,
                NEW_PASSWORD: password,
            },
        }).promise();
        console.log("User confirmed successfully");
        return formatResponse(200, { message: 'Sign-up process is successful' });
    } catch (error) {
        console.error("SignUp error:", error);
        if (error.code === "UsernameExistsException") {
            return formatResponse(400, { message: "User already exists" });
        }
        return formatResponse(400, { message: error.message });
    }
};

const handleSignIn = async (email, password) => {
    console.log("handleSignIn called:", { email });
    try {
        const response = await cognitoSignIn(email, password);
        console.log("cognitoSignIn response:", response);
        if (!response.AuthenticationResult) {
            console.error("AuthenticationResult missing in response");
            return formatResponse(400, { message: "Authentication failed" });
        }
        return formatResponse(200, { accessToken: response.AuthenticationResult.IdToken });
    } catch (error) {
        console.error("SignIn error:", error);
        if (error.code === "NotAuthorizedException" || error.code === "UserNotFoundException") {
            return formatResponse(400, { message: "Invalid email or password" });
        }
        return formatResponse(400, { message: error.message });
    }
};

const cognitoSignIn = async (email, password) => {
    console.log("cognitoSignIn called:", { email });
    const params = {
        AuthFlow: 'ADMIN_NO_SRP_AUTH',
        ClientId: clientId,
        UserPoolId: userPoolId,
        AuthParameters: {
            USERNAME: email,
            PASSWORD: password,
        },
    };
    console.log("cognitoSignIn params:", params);
    return await cognito.adminInitiateAuth(params).promise();
};

// --------------------- TABLES ----------------------------

const handleTableCreate = async ({ id, number, places, isVip, minOrder }) => {
    console.log("handleTableCreate called with:", { id, number, places, isVip, minOrder });
    const params = {
        TableName: tablesTable,
        Item: { id, number, places, isVip, minOrder },
    };
    try {
        console.log("Putting item into DynamoDB with params:", params);
        await docClient.put(params).promise();
        console.log("Table created successfully");
        return formatResponse(200, { id });
    } catch (err) {
        console.error("handleTableCreate error:", err);
        return formatResponse(400, { message: err.message });
    }
};

const handleTableList = async () => {
    console.log("handleTableList called");
    try {
        const data = await docClient.scan({ TableName: tablesTable }).promise();
        console.log("handleTableList data:", data);
        return formatResponse(200, { tables: data.Items });
    } catch (error) {
        console.error("handleTableList error:", error);
        return formatResponse(400, { message: error.message });
    }
};

const handleTableById = async (tableId) => {
    console.log("handleTableById called with tableId:", tableId);
    if (!tableId) {
        console.error("Missing tableId");
        return formatResponse(400, { message: 'Missing id parameter' });
    }
    const params = {
        TableName: tablesTable,
        Key: { id: tableId },
    };
    try {
        const data = await docClient.get(params).promise();
        console.log("handleTableById data:", data);
        if (!data.Item) {
            console.error("Table not found for id:", tableId);
            return formatResponse(404, { message: 'Table not found' });
        }
        return formatResponse(200, data.Item);
    } catch (error) {
        console.error("handleTableById error:", error);
        return formatResponse(400, { message: error.message });
    }
};

const tableByNumber = async (number) => {
    console.log("tableByNumber called with number:", number);
    const data = await docClient.scan({ TableName: tablesTable }).promise();
    console.log("tableByNumber data:", data);
    return data.Items.find((table) => table.number === number);
};

// --------------------- RESERVATIONS ----------------------------

const handleReservationCreate = async ({
                                           tableNumber,
                                           clientName,
                                           phoneNumber,
                                           date,
                                           slotTimeStart,
                                           slotTimeEnd,
                                       }) => {
    console.log("handleReservationCreate called with:", {
        tableNumber,
        clientName,
        phoneNumber,
        date,
        slotTimeStart,
        slotTimeEnd,
    });
    const reservation = { tableNumber, clientName, phoneNumber, date, slotTimeStart, slotTimeEnd };
    const reservationId = uuidv4();
    const params = {
        TableName: reservationsTable,
        Item: {
            id: reservationId,
            tableNumber,
            clientName,
            phoneNumber,
            date,
            slotTimeStart,
            slotTimeEnd,
        },
    };
    try {
        await validateReservation(reservation);
        console.log("Reservation validation passed");
        await docClient.put(params).promise();
        console.log("Reservation created successfully");
        return formatResponse(200, { reservationId });
    } catch (err) {
        console.error("handleReservationCreate error:", err);
        return formatResponse(400, { message: err.message });
    }
};

const validateReservation = async (reservation) => {
    console.log("validateReservation called with:", reservation);
    const table = await tableByNumber(reservation.tableNumber);
    console.log("validateReservation - table:", table);
    if (!table) throw new Error('Table number does not exist');

    const reservationsData = await getReservationByTableNumber(reservation.tableNumber);
    console.log("validateReservation - existing reservations:", reservationsData);
    if (reservationsData.length === 0) return true;

    const invalid = reservationsData.some((actualReservation) => {
        const actualStart = new Date(`${actualReservation.date} ${actualReservation.slotTimeStart}`);
        const actualEnd = new Date(`${actualReservation.date} ${actualReservation.slotTimeEnd}`);
        const reqStart = new Date(`${reservation.date} ${reservation.slotTimeStart}`);
        const reqEnd = new Date(`${reservation.date} ${reservation.slotTimeEnd}`);
        console.log("Comparing times:", { actualStart, actualEnd, reqStart, reqEnd });
        return (actualStart <= reqStart && actualEnd >= reqStart) ||
            (actualStart <= reqEnd && actualEnd >= reqEnd);
    });
    if (invalid) {
        throw new Error('Reservation date overlaps existent reservation');
    } else {
        return true;
    }
};

const getReservationByTableNumber = async (tableNumber) => {
    console.log("getReservationByTableNumber called with tableNumber:", tableNumber);
    const data = await docClient.scan({ TableName: reservationsTable }).promise();
    console.log("getReservationByTableNumber data:", data);
    return data.Items.filter((reservation) => reservation.tableNumber === tableNumber);
};

const handleReservationList = async () => {
    console.log("handleReservationList called");
    try {
        const data = await docClient.scan({ TableName: reservationsTable }).promise();
        console.log("handleReservationList data:", data);
        return formatResponse(200, { reservations: data.Items });
    } catch (error) {
        console.error("handleReservationList error:", error);
        return formatResponse(400, { message: error.message });
    }
};


