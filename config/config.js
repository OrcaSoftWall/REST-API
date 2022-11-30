const env = process.env.NODE_ENV || 'development';

const config = {
    development: {
        port: process.env.PORT || 9999,
        // dbURL: 'mongodb://localhost:27017/rest-api-db',
        dbURL: `mongodb+srv://user:123123abc@softuni.hkggx.mongodb.net/origami?retryWrites=true&w=majority`,
        authCookieName: 'x-auth-token'
    },
    production: {}
};

module.exports = config[env];