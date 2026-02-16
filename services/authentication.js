// Loads environment variables from a .env file into process.env
require("dotenv").config();

// Imports the jsonwebtoken library to work with JWT tokens
const jwt = require("jsonwebtoken");

// Middleware function to authenticate a JWT token
function authenticateToken(req, res, next) {
  // Get the Authorization header from the incoming request
  // Typically formatted as: "Bearer <token>"
  const authHeader = req.headers["authorization"];

  // Extract the token from the header
  // If authHeader exists, split it by space and take the second part
  // Example: "Bearer abc123" → ["Bearer", "abc123"]
  const token = authHeader && authHeader.split(" ")[1];

  // If no token is provided, return HTTP 401 (Unauthorized)
  if (token == null) return res.sendStatus(401);

  // Verify the token using the secret key stored in environment variables
  jwt.verify(token, process.env.ACCESS_TOKEN, (err, response) => {
    // If verification fails (invalid or expired token),
    // return HTTP 403 (Forbidden)
    if (err) return res.sendStatus(403);

    // If verification succeeds,
    // store the decoded token payload in res.locals
    // so it can be accessed in later middleware or route handlers
    res.locals = response;

    // Pass control to the next middleware/route handler
    next();
  });
}

// Export the middleware function so it can be used in other files
module.exports = { authenticateToken: authenticateToken };

// | Thing                | What It Does                       |
// | -------------------- | ---------------------------------- |
// | `next()`             | Moves to the next middleware       |
// | `res.locals`         | Temporary storage for this request |
// | Not calling `next()` | Request stops                      |
