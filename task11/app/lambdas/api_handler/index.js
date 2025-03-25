const AWS = require('aws-sdk');
const cognito = new AWS.CognitoIdentityServiceProvider();
const dynamodb = new AWS.DynamoDB.DocumentClient();


const TABLES_TABLE = process.env.tables_table || 'Tables';
const RESERVATIONS_TABLE = process.env.reservations_table || 'Reservations';

exports.handler = async (event) => {
    console.log('Event received:', JSON.stringify(event));
    const { path, httpMethod, body, pathParameters } = event;

    try {
        // signin
        if (path === '/signin' && httpMethod === 'POST') {
            const params = JSON.parse(body);
            const result = await signIn(params);
            return buildResponse(200, result);

            //signup
        } else if (path === '/signup' && httpMethod === 'POST') {
            const params = JSON.parse(body);
            const result = await signUp(params);
            return buildResponse(200, result);

            //list of tables
        } else if (path === '/tables' && httpMethod === 'GET') {
            const data = await dynamodb.scan({ TableName: TABLES_TABLE }).promise();
            return buildResponse(200, data.Items);

            //new table
        } else if (path === '/tables' && httpMethod === 'POST') {
            const item = JSON.parse(body);
            await dynamodb.put({ TableName: TABLES_TABLE, Item: item }).promise();
            return buildResponse(201, { message: 'The table was successfully created.' });

            //information about a specific table (using the tableId parameter)
        } else if (path === '/tables/{tableId}' && httpMethod === 'GET') {
            const tableId = pathParameters.tableId;
            const data = await dynamodb.get({
                TableName: TABLES_TABLE,
                Key: { id: tableId }
            }).promise();
            if (!data.Item) return buildResponse(404, { message: 'Table not found' });
            return buildResponse(200, data.Item);

            //Getting a list of reservations
        } else if (path === '/reservations' && httpMethod === 'GET') {
            const data = await dynamodb.scan({ TableName: RESERVATIONS_TABLE }).promise();
            return buildResponse(200, data.Items);

            // Create a new booking
        } else if (path === '/reservations' && httpMethod === 'POST') {
            const item = JSON.parse(body);
            await dynamodb.put({ TableName: RESERVATIONS_TABLE, Item: item }).promise();
            return buildResponse(201, { message: 'Reservation successfully created' });

        } else {
            return buildResponse(404, { message: 'Resource not found' });
        }
    } catch (err) {
        console.error('Error processing request:', err);
        return buildResponse(500, { message: 'Internal Server Error', error: err.message });
    }
};

//generating a response in the API Gateway proxy integration format
const buildResponse = (statusCode, body) => {
    return {
        statusCode,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        isBase64Encoded: false
    };
};

// handle signin logic via Cognito
const signIn = async (params) => {
    const { username, password } = params;
    const authParams = {
        AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
        UserPoolId: process.env.cup_id,
        ClientId: process.env.cup_client_id,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password
        }
    };
    const result = await cognito.adminInitiateAuth(authParams).promise();
    return result.AuthenticationResult;
};

//handling signup logic via Cognito
const signUp = async (params) => {
    const { username, email, temporaryPassword } = params;
    const createParams = {
        UserPoolId: process.env.cup_id,
        Username: username,
        UserAttributes: [
            { Name: 'email', Value: email }
        ],
        TemporaryPassword: temporaryPassword,
        MessageAction: 'SUPPRESS'
    };
    const result = await cognito.adminCreateUser(createParams).promise();
    return { message: 'User created successfully', result };
};