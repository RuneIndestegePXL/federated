const fs = require('fs');
const path = require('path');
const https = require('https');
const { ApolloServer } = require('@apollo/server');
//const { startStandaloneServer } = require('@apollo/server/standalone');
const { ApolloGateway, IntrospectAndCompose, RemoteGraphQLDataSource } = require('@apollo/gateway');
const { ApolloServerPluginLandingPageLocalDefault } = require('@apollo/server/plugin/landingPage/default');
//const { createComplexityPlugin } = require('graphql-query-complexity');
const { createComplexityRule } = require('graphql-query-complexity')
//const responseCachePlugin = require('@apollo/server-plugin-response-cache');
const rateLimit = require('express-rate-limit');
const depthLimit = require('graphql-depth-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const { parse } = require('graphql');
const {expressMiddleware} = require("@apollo/server/express4");
const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Enhance the logger to capture more details
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

        if (request.variables) {
            request.variables = this.sanitizeVariables(request.variables);
        }

        if (context && context.clientIp) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Forwarded-For'] = context.clientIp;
        }

        if (context && context.requestId) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Request-ID'] = context.requestId;
        }
    }

    sanitizeVariables(variables) {
        if (!variables || typeof variables !== 'object') return variables;

        const sanitized = {};
        for (const [key, value] of Object.entries(variables)) {
            if (typeof value === 'string') {
                sanitized[key] = this.sanitizeString(value);
            } else if (Array.isArray(value)) {
                sanitized[key] = value.map(item =>
                    typeof item === 'object' ? this.sanitizeVariables(item) :
                        typeof item === 'string' ? this.sanitizeString(item) : item
                );
            } else if (value && typeof value === 'object') {
                sanitized[key] = this.sanitizeVariables(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }

    sanitizeString(str) {
        let sanitized = str.replace(/(\b)(on\S+)(\s*)=|javascript:|expression\s*\(|eval\s*\(|new\s+Function|document\.|window\.|alert|confirm|prompt/gi, '');

        sanitized = sanitized.replace(/('|"|\)|\(|;|--|\/\*|\*\/|\\)/g, match => `\\${match}`);

        return sanitized;
    }
}

const gateway = new ApolloGateway({
    supergraphSdl: new IntrospectAndCompose({
        subgraphs: [
            { name: 'order-service', url: "http://order-service.usecase-ace.svc.cluster.local:8080/graphql" },
            { name: 'crm-proxy', url: "http://crm-proxy.usecase-ace.svc.cluster.local:8083/graphql" },
            { name: 'product-service', url: "http://prisma.usecase-ace.svc.cluster.local:4001/graphql" }
            // { name: 'order-service', url: "https://order-service-usecase-ace.apps.sandbox.id.internal/graphql" },
            // { name: 'crm-proxy', url: "https://crm-proxy-usecase-ace.apps.sandbox.id.internal/graphql" },
            // { name: 'product-service', url: "https://prisma-usecase-ace.apps.sandbox.id.internal/graphql" }
        ],
        introspectionHeaders: {
            'User-Agent': 'Apollo-Gateway'
        },
        logger: {
            debug: (message) => logger.info(`Composition: ${message}`),
            info: (message) => logger.info(`Composition: ${message}`),
            warn: (message) => logger.warn(`Composition: ${message}`),
            error: (message) => logger.error(`Composition: ${message}`)
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

// Patch the ApolloGateway's methods that might be using 'find'
const originalBuildService = gateway.buildService;
gateway.buildService = function(options) {
    try {
        return originalBuildService.call(this, options);
    } catch (error) {
        logger.error('Error in buildService:', error);
        throw error;
    }
};

const complexityRule = createComplexityRule({
    maximumComplexity: 1000,
    onComplete: (complexity) => {
        logger.info(`Query complexity: ${complexity}`);
    },
    createError: (max, actual) => {
        return new Error(`Query is too complex: ${actual}. Maximum allowed complexity: ${max}`);
    }
});

function validateQuery(query) {
    try {
        if (typeof query !== 'string') {
            logger.warn(`Query validation received non-string query: ${typeof query}`);
            return null;
        }
        
        const parsedQuery = parse(query);
        const queryString = query.toString().toLowerCase();

        const suspiciousPatterns = [
            'sleep(', 'benchmark(', 'pg_sleep', 'waitfor delay',
            'execute immediate', 'having 1=1', 'union select',
            'script>', '<script', 'onerror=', 'javascript:'
        ];

        for (const pattern of suspiciousPatterns) {
            if (queryString.includes(pattern)) {
                throw new Error('Potentially malicious query detected');
            }
        }

        return parsedQuery;
    } catch (error) {
        logger.error('Query validation failed:', error);
        throw new Error(`Query validation failed: ${error.message}`);
    }
}

async function startGateway() {
    try {
        // Attach unhandled rejection handler to catch any promise errors
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', { reason, promise });
        });

        const server = new ApolloServer({
            gateway,
            subscriptions: false,
            introspection: process.env.NODE_ENV !== 'production',
            plugins: [
                {
                    async requestDidStart(requestContext) {
                        try {
                            logger.info(`Request started: ${JSON.stringify({
                                operationName: requestContext.request?.operationName || 'unknown',
                                query: requestContext.request?.query ? 'present' : 'not present',
                                variables: requestContext.request?.variables ? 'present' : 'not present'
                            })}`);
                            
                            if (requestContext.request && requestContext.request.query) {
                                validateQuery(requestContext.request.query);
                            }

                            const requestId = require('crypto').randomUUID();
                            requestContext.contextValue = requestContext.contextValue || {};
                            requestContext.contextValue.requestId = requestId;

                            return {
                                async didResolveOperation({ request, document }) {
                                    try {
                                        if (!document) {
                                            logger.warn(`No document available for operation ${request?.operationName || 'unknown'}`);
                                            return;
                                        }
                                        
                                        const maxDepth = 10;
                                        const depths = depthLimit(maxDepth)(document, {}, {});

                                        if (depths && depths.length > 0) {
                                            throw new Error(`Query exceeds maximum depth of ${maxDepth}`);
                                        }
                                    } catch (error) {
                                        logger.error('Error in didResolveOperation:', error);
                                        throw error;
                                    }
                                },
                                async didEncounterErrors(requestContext) {
                                    try {
                                        const errors = requestContext.errors || [];
                                        logger.error(`Request ${requestId} errors:`, errors.map(e => e.message || e).join(', '));
                                        
                                        errors.forEach((error, index) => {
                                            logger.error(`Error ${index + 1}:`, {
                                                message: error.message,
                                                path: error.path,
                                                locations: error.locations,
                                                stack: error.stack
                                            });
                                        });
                                    } catch (error) {
                                        logger.error('Error in didEncounterErrors:', error);
                                    }
                                },
                                async willSendResponse(requestContext) {
                                    logger.info(`Request ${requestId} completed: ${requestContext.request.operationName || 'anonymous operation'}`);
                                }
                            };
                        } catch (error) {
                            logger.error('Error in requestDidStart:', error);
                            return {
                                async didEncounterErrors(requestContext) {
                                    logger.error('Errors from earlier failure:', requestContext.errors);
                                }
                            };
                        }
                    }
                },
                ApolloServerPluginLandingPageLocalDefault({ embed: true })
            ],
            validationRules: [
                depthLimit(10),
                complexityRule
            ],
            formatError: (error) => {
                logger.error('Formatted error:', { 
                    message: error.message, 
                    locations: error.locations,
                    path: error.path,
                    stack: error.stack || 'No stack trace',
                    originalError: error.originalError ? error.originalError.toString() : 'No original error'
                });
                
                // Check for specific find() error to provide more details
                if (error.message && error.message.includes('Cannot read properties of undefined (reading \'find\')')) {
                    logger.debug('Find error detected - operation context:' + 
                        JSON.stringify(error.extensions?.context || {}));
                }
                
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
                workerSrc: ["'self'", "blob:"],
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

    // Rate limiting
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 100,
        standardHeaders: true,
        legacyHeaders: false,
        message: 'Too many requests, please try again after 15 minutes',
        skipFailedRequests: true,
        keyGenerator: (req) => {
            return req.ip || req.socket.remoteAddress || '127.0.0.1';
        },
        validate: { trustProxy: false }
    });
    app.use(limiter);
    
    app.set('trust proxy', 1);

    app.use(xss());
    app.use(express.json({ limit: '100kb' }));
    app.use((req, res, next) => {
        logger.info(`${req.method} ${req.originalUrl} - ${req.ip}`);
        next();
    });

    app.use((req, res, next) => {
        if (req.body && typeof req.body === 'object' && req.body.query && typeof req.body.query === 'string') {
            try {
                const query = req.body.query.toLowerCase();
                const suspiciousTerms = ['union select', 'information_schema', 'sleep(', '--', '/*', '*/'];

                if (suspiciousTerms.some(term => query.includes(term))) {
                    return res.status(403).json({
                        errors: [{ message: 'Forbidden query pattern detected' }]
                    });
                }
            } catch (error) {
                logger.error('Error in security middleware:', error);
            }
        }
        next();
    });

    app.use('/',
        cors({
            origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
            credentials: true,
            methods: ['POST', 'OPTIONS', 'GET', 'PATCH', 'DELETE'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            maxAge: 86400
        }),
        (req, res, next) => {
            try {
                if (req.body && req.body.query) {
                    logger.info(`Processing GraphQL query: ${req.body.query.substring(0, 50)}...`);
                }
                next();
            } catch (error) {
                logger.error('Error in pre-Apollo middleware:', error);
                res.status(400).json({
                    errors: [{ message: 'Invalid request format' }]
                });
            }
        },
        (req, res, next) => {
            // Add global error handler middleware for Express
            try {
                const originalEnd = res.end;
                res.end = function(...args) {
                    if (res.statusCode >= 400) {
                        logger.error(`Error response: ${res.statusCode}`, { 
                            body: res._body,
                            path: req.path,
                            query: req.body?.query?.substring(0, 100)
                        });
                    }
                    return originalEnd.apply(this, args);
                };
                next();
            } catch (error) {
                logger.error('Error in response interceptor:', error);
                next();
            }
        },
        (err, req, res, next) => {
            // Express error handler
            logger.error('Express middleware error:', err);
            next(err);
        },
        expressMiddleware(server, {
            context: async ({ req }) => {
                try {
                    const context = {
                        clientIp: req.ip || req.socket?.remoteAddress || '127.0.0.1',
                        userAgent: req.headers ? req.headers['user-agent'] : undefined,
                        requestId: require('crypto').randomUUID()
                    };
                    logger.info(`Created context: ${JSON.stringify(context)}`);
                    return context;
                } catch (error) {
                    logger.error("Error creating context:", error);
                    return {
                        clientIp: '127.0.0.1',
                        requestId: require('crypto').randomUUID()
                    };
                }
            }
        })
    );

    const port = process.env.GATEPORT || 4000;
    app.listen(port, () => {
        console.log(`🚀 Federated Gateway ready at https://url:${port}`);
    });
}

startGateway().catch(err => {
    console.error('Failed to start gateway:', err);
    process.exit(1);
});