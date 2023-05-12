const fs = require("fs");
const bodyParser = require("body-parser");
const jsonServer = require("json-server");
const middlewares = jsonServer.defaults();
const multer = require("multer");
const jwt = require("jsonwebtoken");
const { log } = require("console");

const server = jsonServer.create();

const router = jsonServer.router("./db.json");

let data = JSON.parse(fs.readFileSync("./db.json", "UTF-8"));
let userdb = data.Users;

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
    err !== undefined ? decode : err
  );
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  data = JSON.parse(fs.readFileSync("./db.json", "UTF-8"));
  userdb = data.Users;
  const indexUser = userdb.findIndex(
    (user) => user.email === email && user.password === password
  );
  if (indexUser !== -1) return userdb[indexUser];
  return false;
}

function findUserByEmail(email) {
  const indexUser = userdb.findIndex((user) => user.email === email);

  if (indexUser !== -1) return userdb[indexUser];
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
  const { id, fullName, address, phone, photo, gender, birthday } = userAccess;
  const access_token = createToken({
    email,
    id,
    fullName,
    address,
    phone,
    photo,
    gender,
    birthday,
  });
  res.status(200).json({ access_token });
});

server.post("/auth/refreshtoken", (req, res) => {
  const { email } = req.body;
  const userAccess = findUserByEmail(email);
  if (userAccess === false) {
    const status = 401;
    const message = "Incorrect email";
    res.status(status).json({ status, message });
    return;
  }
  const { id, fullName, address, phone, photo, gender, birthday } = userAccess;
  const access_token = createToken({
    email,
    id,
    fullName,
    address,
    phone,
    photo,
    gender,
    birthday,
  });
  res.status(200).json({ access_token });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/images");
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

server.use(jsonServer.bodyParser);
server.use(middlewares);

server.post("/images", upload.single("image"), (req, res) => {
  const image = {
    id: Date.now(),
    url: `http://localhost:3000/images/${req.file.filename}`,
  };

  res.status(201).json(image);
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
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req.headers.authorization.split(" ")[1]);
    if (verifyTokenResult === undefined) {
      const status = 401;
      const message = "Access token is expired";
      res.status(status).json({ status, message });
      return;
    }
    next();
  } catch (err) {
    const status = 401;
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(3000, () => {
  console.log("Run Auth API Server");
});
