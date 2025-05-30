const fs = require('fs');
const path = require('path');
const https = require('https');
const { ApolloServer } = require('@apollo/server');
const { ApolloGateway, IntrospectAndCompose, RemoteGraphQLDataSource } = require('@apollo/gateway');
const { ApolloServerPluginLandingPageLocalDefault } = require('@apollo/server/plugin/landingPage/default');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const { parse, validate, specifiedRules } = require('graphql');
const {expressMiddleware} = require("@apollo/server/express4");
const express = require('express');
const cors = require('cors');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
require('dotenv').config();

const logger = {
    info: (message) => console.log(`[INFO] ${message}`),
    warn: (message) => console.warn(`[WARN] ${message}`),
    error: (message, err) => {
        if (err && err.stack) {
            console.error(`[ERROR] ${message}`, err);
            console.error(`[ERROR STACK] ${err.stack}`);
        } else {
            console.error(`[ERROR] ${message}`, err || '');
        }
    },
    debug: (message) => console.log(`[DEBUG] ${message}`)
};

const SERVICE_CA_PATH = '/run/secrets/kubernetes.io/serviceaccount/service-ca.crt';
let secureAgent;

try {
    if (fs.existsSync(SERVICE_CA_PATH)) {
        const caCert = fs.readFileSync(SERVICE_CA_PATH);
        secureAgent = new https.Agent({
            ca: caCert,
            rejectUnauthorized: false 
        });
        logger.info('Successfully loaded service CA certificate');
    } else {
        logger.warn('Service CA certificate not found at: ' + SERVICE_CA_PATH);
        secureAgent = new https.Agent({
            rejectUnauthorized: false 
        });
    }
} catch (error) {
    logger.error('Error loading service CA certificate:', error);
    secureAgent = new https.Agent({
        rejectUnauthorized: false
    });
}

class SecureDataSource extends RemoteGraphQLDataSource {
    willSendRequest({ request, context }) {
        request.http = request.http || {};
        request.http.agent = secureAgent;

        if (context && context.clientIp) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Forwarded-For'] = context.clientIp;
        }

        if (context && context.requestId) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Request-ID'] = context.requestId;
        }
    }
}

const gateway = new ApolloGateway({
    debug: true, 
    __exposeQueryPlanExperimental: true, 
    supergraphSdl: new IntrospectAndCompose({
        subgraphs: [
            { 
                name: 'order-service', 
                url: process.env.ORDER_SERVICE_URL
            },
            { 
                name: 'crm-proxy', 
                url: process.env.CRM_PROXY_URL
            },
            { 
                name: 'product-service', 
                url: process.env.PRODUCT_SERVICE_URL
            }
        ],
        introspectionHeaders: {
            'User-Agent': 'Apollo-Gateway'
        }
    }),
    serviceHealthCheck: true,
    buildService({ name, url }) {
        return new SecureDataSource({
            url,
            httpAgent: secureAgent,
            httpsAgent: secureAgent
        });
    }
});

function validateQuery(query) {
    try {
        const parsedQuery = parse(query);
        const queryString = query.toLowerCase();
        
        const sqlPatterns = [
            'union select', 'select *', 'select 1', 'select @@version',
            'waitfor delay', 'sleep(', 'benchmark(', 'pg_sleep',
            'having 1=1', 'or 1=1', 'and 1=1',
            'exec ', 'execute ', 'sp_executesql',
            'insert into', 'update set', 'delete from',
            'drop table', 'drop database', 'create table',
            'alter table', 'sys.tables', 'information_schema',
            '--', '/*', '*/", "#', '\'\'=\'\''
        ];
        
        const xssPatterns = [
            '<script>', '</script>', 'javascript:', 'onerror=',
            'onload=', 'eval(', 'document.cookie', 'alert(',
            'String.fromCharCode(', 'fromCharCode',
            'expression(', 'url(javascript', '<img src=',
            'document.write', 'window.location'
        ];
        
        const injectionPatterns = [...sqlPatterns, ...xssPatterns];
        
        for (const pattern of injectionPatterns) {
            if (queryString.includes(pattern)) {
                logger.warn(`Security pattern detected in query: ${pattern}`);
                throw new Error('Potentially malicious query detected');
            }
        }
        
        return parsedQuery;
    } catch (error) {
        logger.error('Query validation error:', error);
        throw new Error(`Query validation failed: ${error.message}`);
    }
}

async function startGateway() {
    let server;

    try {
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', reason);
        });
        server = new ApolloServer({
            gateway,
            introspection: true,
            plugins: [
                ApolloServerPluginLandingPageLocalDefault({ embed: true }),
                {
                    async requestDidStart() {
                        return {
                            async willSendResponse(requestContext) {
                                if (requestContext.errors) {
                                    logger.error('GraphQL errors:', requestContext.errors);
                                }
                            },
                            async didReceiveOperation({ request, document }) {
                                try {
                                    if (request.query) {
                                        validateQuery(request.query);
                                    }
                                } catch (error) {
                                    throw new Error(`Security validation failed: ${error.message}`);
                                }
                            }
                        };
                    }
                }
            ],
            validationRules: [],
            formatError: (error) => {
                if (error.message && error.message.includes('find')) {
                    logger.error('FIND ERROR DETECTED - Full context:', error);
                    try {
                        throw new Error('Stack trace for find error');
                    } catch (e) {
                        logger.error('Stack trace at find error point:', e.stack);
                    }
                }
                
                logger.error('GraphQL error:', error);
                if (process.env.NODE_ENV === 'production') {
                    return new Error('Internal server error');
                }
                return error;
            }
        });
        
        await server.start();
    } catch (error) {
        logger.error('Error initializing Apollo Server:', error);
        throw error;
    }

    const app = express();
    app.use('/graphql', (req, res, next) => {
        if (req.method === 'POST' && req.body && req.body.query) {
            try {
                logger.debug('Pre-Apollo GraphQL request:', req.body.query.substring(0, 100));
                try {
                    const parsedQuery = parse(req.body.query);
                    logger.debug('Query parsed successfully');
                } catch (parseError) {
                    logger.error('Query parse error:', parseError);
                }
            } catch (error) {
                logger.error('Error in diagnostics middleware:', error);
            }
        }
        next();
    });

    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        xssFilter: true,
        noSniff: true,
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        },
        frameguard: {
            action: 'deny'
        },
        referrerPolicy: { policy: 'same-origin' }
    }));

    app.set('trust proxy', 1);
    app.use(xss());
    app.use(express.json({ 
        limit: '100kb',
        verify: (req, res, buf) => {
            try {
                JSON.parse(buf);
            } catch (e) {
                res.status(400).json({ errors: [{ message: 'Invalid JSON' }] });
                throw new Error('Invalid JSON');
            }
        }
    }));

    app.use((req, res, next) => {
        logger.info(`${req.method} ${req.path} - ${req.ip}`);
        next();
    });
    
    app.use((req, res, next) => {
        if (req.body && req.body.query && typeof req.body.query === 'string') {
            try {
                const query = req.body.query;
                validateQuery(query);                
            } catch (error) {
                logger.error('Query validation error in middleware:', error);
                return res.status(400).json({
                    errors: [{ message: error.message || 'Invalid query' }]
                });
            }
        }
        next();
    });

    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 50,
        standardHeaders: true, 
        legacyHeaders: false, 
    });

    const checkJwt = jwt({
        secret: jwksRsa.expressJwtSecret({
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 5,
            jwksUri: process.env.JWKS_URI
        }),
        algorithms: ['RS256'],
        credentialsRequired: true,
        requestProperty: 'auth'
    });

    const handleJwtError = (err, req, res, next) => {
        if (err.name === 'UnauthorizedError') {
            logger.warn(`JWT validation failed: ${err.message}`);
            return res.status(401).json({
                errors: [{ message: 'Invalid token or missing authentication' }]
            });
        }
        next(err);
    };

    app.use('/',
        cors({
            origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
            methods: ['POST', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            maxAge: 86400
        }),
        limiter,
        checkJwt,
        handleJwtError,
        expressMiddleware(server, {
            context: async ({ req }) => ({
                clientIp: req.ip || '127.0.0.1',
                userAgent: req.headers ? req.headers['user-agent'] : undefined,
                requestId: require('crypto').randomUUID(),
                user: req.auth 
            })
        })
    );

    app.use((err, req, res, next) => {
        logger.error('Express error:', err);
        res.status(500).json({ errors: [{ message: 'Internal server error' }] });
    });

    const port = process.env.GATEPORT || 4000;
    app.listen(port, () => {
        console.log(`🚀 Federated Gateway ready at http://url:${port}`);
    });
}

startGateway().catch(err => {
    console.error('Failed to start gateway:', err);
    process.exit(1);
});