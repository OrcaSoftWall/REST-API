const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const express = require('express');
const secret = 'secret';
const config = require('../config/config');

module.exports = (app) => {
    app.use(cors({
        exposedHeaders: config.authCookieName
    }));

    app.use(express.json());
    app.use(express.urlencoded({
        extended: true
    }))

    //depricated?
    app.use(bodyParser.urlencoded({
        extended: true
    }));

    app.use(cookieParser(secret));
};