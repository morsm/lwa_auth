// -*- coding: utf-8 -*-

// Authenticate LWA token to allow access through nginx
// Returns 200 for allowed, 401 for not allowed

'use strict';

const http = require('http');
const https = require('https');
var Promise = require('promise');
var bodyJson = require("body/json");

// Load list of allowed email addresses. Should contain array of strings under the "addresses" property.
const VALID_EMAILS = require('./emails.json');

// Amazon parameters
const LWA_HOST = "api.amazon.com";

// Setup HTTP server
const server = http.createServer(handleHttpRequest);
const port = 2999;

server.listen(port, (err) => {
    if (err) 
    {
        return console.log("Error creating server", err);
    }

    console.log("lwa_auth running on port", port);
});


async function handleHttpRequest(request, response)
{
    console.log("Request", request.headers["x-original-uri"]);

    // Validate request
    var status = 401;
    var statusMessage = "Unauthorized";
    var message = null;             // The JSON body of the message that was sent to us

    try
    {
        var token = request.headers["authorization"];
        if (token == null) throw ("No authorization header");
        
        await validateToken(token);       // Will throw if not valid or some other error

        status = 200;
        statusMessage = "OK";
    } 
    catch (err)
    {
        console.log("Error or unauthorized", err);
    }

    console.log("Returning status", status, statusMessage);
    response.statusCode = status;
    response.status = statusMessage;
    response.end();
}

async function validateToken(token)
{
    var lwaResponse = await lwaHttpsGetRequest(token);
    console.log("LWA response", lwaResponse);

    // Sill hardcoded email check
    var mailFound = VALID_EMAILS.addresses.find(email => { return email == lwaResponse.email; });
    if (! mailFound) throw("Unknown user " + lwaResponse.email);
}

async function lwaHttpsGetRequest(token)
{
    console.log("Executing HTTP get to LWA");

    return new Promise((resolve, reject) => {
        var options = {
            host: LWA_HOST,
            path: "/user/profile",
            headers:
            {
                "Authorization": token,
                "Accept": "application/json"
            }
        };

        https.get(options, (res) => {
            console.log("Amazon responds ", res.statusCode);

            if (200 == res.statusCode) 
            {
                bodyJson(res, function (err, body) {
                   if (err) reject(err);
                   else resolve(body);
                });
            }
            else reject(res.statusCode);
        });

    });
}

