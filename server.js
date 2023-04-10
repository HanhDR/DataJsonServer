const fs = require("fs");
const bodyParser = require("body-parser");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const { log } = require("console");

const server = jsonServer.create();

const router = jsonServer.router("./db.json");

const userdb = JSON.parse(fs.readFileSync("./users.json", "UTF-8"));

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = "0966906329";
const expiresIn = "1h";

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err
  );
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  const indexUser = userdb.users.findIndex(
    (user) => user.email === email && user.password === password
  );
  if (indexUser !== -1) return userdb.users[indexUser];
  return false;
}

server.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  const userAccess = isAuthenticated({ email, password });
  if (userAccess === false) {
    const status = 401;
    const message = "Incorrect email or password";
    res.status(status).json({ status, message });
    return;
  }
  const { id, fullname, address, phone, photo, gender, birthday } = userAccess;
  const access_token = createToken({
    email,
    id,
    fullname,
    address,
    phone,
    photo,
    gender,
    birthday,
  });
  res.status(200).json({ access_token });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    const status = 401;
    const message = "Bad authorization header";
    res.status(status).json({ status, message });
    return;
  }
  try {
    verifyToken(req.headers.authorization.split(" ")[1]);
    next();
  } catch (err) {
    const status = 401;
    const message = "Error: access_token is not valid";
    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(3000, () => {
  console.log("Run Auth API Server");
});
