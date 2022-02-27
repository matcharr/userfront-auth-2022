// Node.js example (Express.js)

const jwt = require("jsonwebtoken");

function authenticateToken(req, res, next) {
    // Read the JWT access token from the request header
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (token == null) return res.sendStatus(401); // Return 401 if no token

    // Verify the token using the Userfront public key
    jwt.verify(token, process.env.USERFRONT_PUBLIC_KEY, (err, auth) => {
        if (err) return res.sendStatus(403); // Return 403 if there is an error verifying
        req.auth = auth;
        next();
    });
}
console.log(req.auth);
// =>
{
    mode: 'test',
        tenantId: 'demo1234',
            userId: 1,
                userUuid: 'ab53dbdc-bb1a-4d4d-9edf-683a6ca3f609',
                    isConfirmed: false,
                        authorization: {
        demo1234: {
            roles: ["admin"],
    },
    },
    sessionId: '35d0bf4a-912c-4429-9886-cd65a4844a4f',
        iat: 1614114057,
            exp: 1616706057
}

// Node.js example (Express.js)

app.get("/users", (req, res) => {
    const authorization = req.auth.authorization["demo1234"] || {};

    if (authorization.roles.includes("admin")) {
        // Allow access
    } else {
        // Deny access
    }
});