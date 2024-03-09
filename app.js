const express = require("express");

const morgan = require("morgan");

const http = require("http");

const server = http.createServer(app);

const port = process.env.PORT || 8000;

const rateLimit  = require("express-rate-limit");

const helmet = require("helmet")

const mongosanitize = require("express-mongo-sanitize")

const bodyParser = require("body-parser")

const app = express();

app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PATCH", "DELETE", "PUT"],
    credentials: true
}))

app.use(express.json({ limit: "10kb" }))

app.use(bodyParser.json());

const xss = require("xss")

const cors = require("cors")

app.use(bodyParser.urlencoded({extended: true}))

app.use(helmet());

if(process.env.NODE_ENV === "development"){
    app.use(morgan("dev"))
}

const limiter = rateLimit({
    max: 3000,
    windowMs: 60 * 60 * 1000,
    message: "Too many requests from this IP, Please try again in an hour"
})

app.use("/tawk", limiter);

app.use(express.urlencoded({
    extended: true
}))

app.use(mongosanitize())

module.exports = app
